$ErrorActionPreference='Stop'
$testRoot=Join-Path $env:TEMP ('kitobzor-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $testRoot
$base='http://127.0.0.1:8081/api'
$script:server=$null
$script:checks=0
function Start-TestServer {
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'server.ps1')+'" -Port 8081 -DataDirectory "'+$testRoot+'"'
    $script:server=Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testRoot 'server.log') -RedirectStandardError (Join-Path $testRoot 'error.log')
    $available=$false
    for($i=0;$i -lt 30;$i++){
        try{$null=Invoke-RestMethod -Uri "$base/health" -TimeoutSec 1;$available=$true;break}catch{Start-Sleep -Milliseconds 150}
    }
    if(-not $available){throw 'Test server did not start'}
}
function Check($Condition,$Message){if(-not $Condition){throw "FAILED: $Message"};$script:checks++;Write-Output "PASS: $Message"}
function Request($Method,$Path,$Data=$null,$Session=$null,$Headers=@{}){
    $params=@{Uri="$base$Path";Method=$Method;TimeoutSec=8;Headers=$Headers}
    if($Session){$params.WebSession=$Session}
    if($null -ne $Data){$params.ContentType='application/json; charset=utf-8';$params.Body=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Data -Depth 15 -Compress))}
    Invoke-RestMethod @params
}
function Expect-Status($Code,$Action,$Message){try{& $Action | Out-Null;throw 'Expected HTTP error'}catch{if(-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne $Code){throw "FAILED: $Message ($($_.Exception.Message))"}};Check $true $Message}
try{
    Start-TestServer
    $catalog=Request GET '/books';Check ($catalog.books.Count -eq 8) 'Seed contains eight individual books'
    $book=$catalog.books[0];$initialStock=$book.stock
    Check ($book.title -match '^O') 'Catalog loaded with UTF-8 titles'
    Expect-Status 401 {Request GET '/admin/data'} 'Admin data requires authentication'
    Expect-Status 403 {Request POST '/admin/login' @{username='admin';password='wrong'} $null @{Origin='https://untrusted.example'}} 'Foreign-origin writes rejected'
    Expect-Status 401 {Request POST '/admin/login' @{username='admin';password='wrong'}} 'Wrong password rejected'
    $lines=Get-Content -LiteralPath (Join-Path $testRoot 'admin-access.txt')
    $password=($lines | Where-Object {$_ -like 'Password: *'}).Substring(10)
    $session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login=Request POST '/admin/login' @{username='admin';password=$password} $session
    Check $login.authenticated 'Admin can log in'
    Check ((Request GET '/admin/session' $null $session).authenticated) 'Session cookie retained'
    $newBook=@{title='Integration <book>';author='Test Author';category='Adabiyot';price=51000;stock=3;color='#284c41';tag='Test';description='Integration test book description.'}
    $added=Request POST '/admin/books' $newBook $session
    Check ($added.book.id -eq 9) 'Admin creates book with unique ID'
    $newBook.price=52000;$newBook.stock=4
    $changed=Request PUT '/admin/books/9' $newBook $session
    Check ($changed.book.price -eq 52000 -and $changed.book.stock -eq 4) 'Admin edits price and inventory'
    $null=Request PUT '/admin/books/9/archive' @{} $session
    Check (-not ((Request GET '/books').books | Where-Object id -eq 9)) 'Archived book hidden from catalog'
    $null=Request PUT '/admin/books/9/archive' @{} $session
    Check ([bool]((Request GET '/books').books | Where-Object id -eq 9)) 'Admin restores archived book'
    $review=@{bookId=1;name='Test Reader';rating=5;text='A thoughtful review for integration testing.'}
    $null=Request POST '/reviews' $review
    Check ((Request GET '/reviews').reviews.Count -eq 0) 'Pending review not publicly visible'
    Expect-Status 409 {Request POST '/reviews' $review} 'Duplicate review rejected'
    $pending=(Request GET '/admin/data' $null $session).reviews[0]
    $null=Request PUT ('/admin/reviews/'+$pending.id) @{status='approved'} $session
    Check ((Request GET '/reviews').reviews.Count -eq 1) 'Approved review becomes public'
    $invalidReview=@{bookId=1;name='Test Reader';rating=6;text='This should never be accepted.'}
    Expect-Status 400 {Request POST '/reviews' $invalidReview} 'Rating outside 1 to 5 rejected'
    $order=@{requestId=[guid]::NewGuid().ToString();name='Test Customer';phone='+998901234567';delivery='courier';address='Test city, test street, building 10';payment='demo';items=@(@{id=1;quantity=2;price=1})}
    $placed=Request POST '/orders' $order
    Check ($placed.order.total -eq (2*$book.price+25000)) 'Server computes price and delivery, ignores supplied price'
    Check ($placed.order.paymentStatus -eq 'simulated') 'Demo payment explicitly simulated'
    Check (((Request GET '/books').books | Where-Object id -eq 1).stock -eq ($initialStock-2)) 'Checkout decrements stock'
    $retry=Request POST '/orders' $order
    Check ($retry.order.id -eq $placed.order.id) 'Retry returns same order without duplicate'
    Check (((Request GET '/books').books | Where-Object id -eq 1).stock -eq ($initialStock-2)) 'Idempotent retry leaves stock unchanged'
    Expect-Status 404 {Request GET ('/orders/'+$placed.order.id)} 'Receipt requires private token'
    $receipt=Request GET ('/orders/'+$placed.order.id) $null $null @{'X-Order-Token'=$placed.receiptToken}
    Check ($receipt.order.id -eq $placed.order.id) 'Customer can read receipt using its token'
    $order.requestId=[guid]::NewGuid().ToString();$order.items=@(@{id=1;quantity=99})
    Expect-Status 409 {Request POST '/orders' $order} 'Overselling rejected'
    $order.requestId=[guid]::NewGuid().ToString();$order.items=@(@{id=1;quantity=0})
    Expect-Status 400 {Request POST '/orders' $order} 'Zero quantity rejected'
    $order.requestId=[guid]::NewGuid().ToString();$order.items=@(@{id=1;quantity=1},@{id=1;quantity=1})
    Expect-Status 400 {Request POST '/orders' $order} 'Duplicate book lines rejected'
    foreach($state in @('confirmed','shipped','completed')){$null=Request PUT ('/admin/orders/'+$placed.order.id) @{status=$state} $session}
    Check ((Request GET ('/orders/'+$placed.order.id) $null $null @{'X-Order-Token'=$placed.receiptToken}).order.status -eq 'completed') 'Admin order progress visible to customer'
    Expect-Status 409 {Request PUT ('/admin/orders/'+$placed.order.id) @{status='cancelled'} $session} 'Completed order cannot be cancelled'
    $order.requestId=[guid]::NewGuid().ToString();$order.items=@(@{id=1;quantity=1});$order.delivery='pickup';$order.payment='cash'
    $cancelled=Request POST '/orders' $order
    Check ($cancelled.order.shipping -eq 0 -and $cancelled.order.paymentStatus -eq 'unpaid') 'Pickup is free and cash remains unpaid'
    $null=Request PUT ('/admin/orders/'+$cancelled.order.id) @{status='cancelled'} $session
    Check (((Request GET '/books').books | Where-Object id -eq 1).stock -eq ($initialStock-2)) 'Cancellation restores inventory exactly once'
    Expect-Status 409 {Request PUT ('/admin/orders/'+$cancelled.order.id) @{status='cancelled'} $session} 'Repeated cancellation cannot inflate stock'
    $null=Request POST '/admin/logout' @{} $session
    Expect-Status 401 {Request GET '/admin/data' $null $session} 'Logout invalidates session'
    Stop-Process -Id $script:server.Id
    Start-TestServer
    Check ((Request GET '/books').books.Count -eq 9) 'Catalog persists after server restart'
    Check ((Request GET '/reviews').reviews.Count -eq 1) 'Moderated reviews persist after restart'
    Check ((Request GET ('/orders/'+$placed.order.id) $null $null @{'X-Order-Token'=$placed.receiptToken}).order.status -eq 'completed') 'Order and receipt persist after restart'
    Write-Output "All $script:checks integration checks passed. User data was not modified."
}finally{if($script:server -and -not $script:server.HasExited){Stop-Process -Id $script:server.Id}}
