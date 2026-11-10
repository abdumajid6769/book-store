param([int]$Port = 8080, [string]$DataDirectory = '')
$ErrorActionPreference = 'Stop'
$webRoot = Join-Path $PSScriptRoot 'dist'
$dataRoot = if($DataDirectory){$DataDirectory}else{Join-Path $PSScriptRoot 'data'}
$null = New-Item -ItemType Directory -Path $dataRoot -Force
$dbPath = Join-Path $dataRoot 'store.json'
$utf8 = [Text.UTF8Encoding]::new($false)
function Write-AtomicJson($Path, $Value) {
    [IO.File]::WriteAllText("$Path.tmp", (ConvertTo-Json -InputObject $Value -Depth 30), $utf8)
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace("$Path.tmp", $Path, "$Path.bak", $true);[IO.File]::Delete("$Path.bak") }
    else { [IO.File]::Move("$Path.tmp", $Path) }
}
function New-Token {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes); $rng.Dispose()
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Password-Hash($Password, $Salt) {
    $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new([string]$Password, [Convert]::FromBase64String($Salt), 120000)
    try { return [Convert]::ToBase64String($derive.GetBytes(32)) } finally { $derive.Dispose() }
}
if (-not (Test-Path -LiteralPath $dbPath)) {
    $seedBooks=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'seed.json') | ConvertFrom-Json
    Write-AtomicJson $dbPath ([ordered]@{books=@($seedBooks | ForEach-Object {$_});reviews=@();orders=@()})
}
$script:db = Get-Content -Raw -Encoding UTF8 -LiteralPath $dbPath | ConvertFrom-Json
if($script:db.books.Count -eq 1 -and $script:db.books[0] -is [array]){$script:db.books=$script:db.books[0];Write-AtomicJson $dbPath $script:db}
if($script:db.books[0].PSObject.Properties['value']){$script:db.books=@($script:db.books[0].value | ForEach-Object {$_});Write-AtomicJson $dbPath $script:db}
$authPath = Join-Path $dataRoot 'admin-auth.json'
if (-not (Test-Path -LiteralPath $authPath)) {
    $password = (New-Token).Substring(0,18)
    $salt = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((New-Token)))
    Write-AtomicJson $authPath @{ salt=$salt; hash=(Password-Hash $password $salt) }
    $accessPath=if($DataDirectory){Join-Path $dataRoot 'admin-access.txt'}else{Join-Path $PSScriptRoot 'admin-access.txt'}
    [IO.File]::WriteAllText($accessPath, "Kitobzor local admin`r`nURL: http://localhost:$Port/#admin`r`nLogin: admin`r`nPassword: $password`r`n`r`nKeep this file private. The server never serves this file.`r`n", $utf8)
    $password=$null
}
$auth = Get-Content -Raw -Encoding UTF8 -LiteralPath $authPath | ConvertFrom-Json
$sessions=@{}; $script:loginFails=0; $script:lockedUntil=[DateTime]::MinValue
function Save-Database { Write-AtomicJson $dbPath $script:db }
function Reply($Status, $Value, $Cookie='') { return @{status=$Status;body=(ConvertTo-Json -InputObject $Value -Depth 30 -Compress);type='application/json; charset=utf-8';cookie=$Cookie} }
function Fail($Message, $Status=400) { return (Reply $Status @{error=$Message}) }
function Text-Field($Value, $Min, $Max) {
    if ($Value -isnot [string]) { throw 'Invalid text field' }
    $text=$Value.Trim()
    if ($text.Length -lt $Min -or $text.Length -gt $Max) { throw 'Invalid text length' }
    return $text
}
function Whole-Number($Value, $Min, $Max) {
    if ($null -eq $Value -or $Value -is [bool] -or [string]$Value -notmatch '^\d+$') { throw 'Invalid number' }
    $number=[long]$Value
    if ($number -lt $Min -or $number -gt $Max) { throw 'Number outside allowed range' }
    return $number
}
function Public-Order($Order) { return @{id=$Order.id;createdAt=$Order.createdAt;items=$Order.items;subtotal=$Order.subtotal;shipping=$Order.shipping;total=$Order.total;delivery=$Order.delivery;payment=$Order.payment;paymentStatus=$Order.paymentStatus;status=$Order.status;customer=$Order.customer} }
function Handle-Api($Method, $Path, $Headers, $Payload) {
    $isAdmin=$false; $sessionKey=''
    if ($Headers['cookie'] -match '(?:^|;\s*)kitobzor_admin=([A-Za-z0-9_-]+)') {
        $sessionKey=$Matches[1]
        if ($sessions.ContainsKey($sessionKey)) {
            if ($sessions[$sessionKey] -gt [DateTime]::UtcNow) { $isAdmin=$true } else { $sessions.Remove($sessionKey) }
        }
    }
    if ($Method -notin @('GET','HEAD') -and $Headers['origin'] -and $Headers['origin'] -notin @("http://localhost:$Port","http://127.0.0.1:$Port")) { return (Fail 'Origin rejected' 403) }
    if ($Path -eq '/api/health' -and $Method -eq 'GET') { return (Reply 200 @{ok=$true;mode='local'}) }
    if ($Path -eq '/api/admin/session' -and $Method -eq 'GET') { return (Reply 200 @{authenticated=$isAdmin}) }
    if ($Path -eq '/api/admin/login' -and $Method -eq 'POST') {
        if ([DateTime]::UtcNow -lt $script:lockedUntil) { return (Fail 'Too many attempts. Retry in one minute.' 429) }
        if ($Payload.username -ne 'admin' -or (Password-Hash ([string]$Payload.password) $auth.salt) -ne $auth.hash) {
            $script:loginFails++
            if ($script:loginFails -ge 5) { $script:lockedUntil=[DateTime]::UtcNow.AddMinutes(1);$script:loginFails=0 }
            return (Fail 'Login yoki parol xato' 401)
        }
        $script:loginFails=0; $token=New-Token; $sessions[$token]=[DateTime]::UtcNow.AddHours(8)
        return (Reply 200 @{authenticated=$true} "kitobzor_admin=$token; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800")
    }
    if ($Path -eq '/api/admin/logout' -and $Method -eq 'POST') {
        if ($sessionKey) { $sessions.Remove($sessionKey) }
        return (Reply 200 @{ok=$true} 'kitobzor_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
    }
    if ($Path -eq '/api/books' -and $Method -eq 'GET') { return (Reply 200 @{books=@($script:db.books | Where-Object {-not $_.archived})}) }
    if ($Path -eq '/api/reviews' -and $Method -eq 'GET') { return (Reply 200 @{reviews=@($script:db.reviews | Where-Object status -eq 'approved' | Select-Object id,bookId,name,rating,text,createdAt)}) }
    if ($Path -eq '/api/reviews' -and $Method -eq 'POST') {
        $bookId=Whole-Number $Payload.bookId 1 99999999
        if (-not ($script:db.books | Where-Object {$_.id -eq $bookId -and -not $_.archived})) { return (Fail 'Kitob topilmadi' 404) }
        $name=Text-Field $Payload.name 2 60; $text=Text-Field $Payload.text 10 2000; $rating=Whole-Number $Payload.rating 1 5
        if (@($script:db.reviews | Where-Object {$_.bookId -eq $bookId -and $_.name -eq $name -and $_.text -eq $text}).Count) { return (Fail 'Bu sharh avval yuborilgan' 409) }
        $review=[pscustomobject]@{id=[guid]::NewGuid().ToString('N');bookId=$bookId;name=$name;text=$text;rating=$rating;status='pending';createdAt=[DateTime]::UtcNow.ToString('o')}
        $script:db.reviews=@($script:db.reviews)+$review; Save-Database
        return (Reply 201 @{ok=$true;message='Sharh tekshirish uchun yuborildi'})
    }
    if ($Path -eq '/api/orders' -and $Method -eq 'POST') {
        $requestId=Text-Field $Payload.requestId 20 80
        if ($requestId -notmatch '^[a-zA-Z0-9-]+$') { return (Fail 'Invalid request ID') }
        $existing=$script:db.orders | Where-Object requestId -eq $requestId | Select-Object -First 1
        if ($existing) { return (Reply 200 @{order=(Public-Order $existing);receiptToken=$existing.receiptToken}) }
        $name=Text-Field $Payload.name 2 100; $phone=Text-Field $Payload.phone 9 25
        if ($phone -notmatch '^\+?[0-9 ()-]{9,25}$' -or ($phone -replace '\D','').Length -notin @(9,12)) { return (Fail 'Telefon raqamini tekshiring') }
        if ($Payload.delivery -notin @('pickup','courier')) { return (Fail 'Invalid delivery') }
        if ($Payload.payment -notin @('cash','demo')) { return (Fail 'Invalid payment') }
        $address=''
        if ($Payload.delivery -eq 'courier') { $address=Text-Field $Payload.address 10 300 }
        if (@($Payload.items).Count -lt 1 -or @($Payload.items).Count -gt 50) { return (Fail 'Savatcha bosh yoki juda katta') }
        $items=@();$subtotal=0;$seen=@{}
        foreach ($line in $Payload.items) {
            $id=Whole-Number $line.id 1 99999999; $qty=Whole-Number $line.quantity 1 99
            if ($seen.ContainsKey([string]$id)) { return (Fail 'Duplicate book') };$seen[[string]$id]=$true
            $book=$script:db.books | Where-Object {$_.id -eq $id -and -not $_.archived} | Select-Object -First 1
            if (-not $book -or $book.stock -lt $qty) { return (Fail 'Kitob mavjud emas yoki zaxira yetarli emas' 409) }
            $items += [pscustomobject]@{id=$id;title=$book.title;quantity=$qty;price=$book.price};$subtotal+=$book.price*$qty
        }
        $shipping=0;if($Payload.delivery -eq 'courier'){$shipping=25000}
        $order=[pscustomobject]@{id=('KZ-'+[guid]::NewGuid().ToString('N').Substring(0,12).ToUpper());requestId=$requestId;receiptToken=(New-Token);createdAt=[DateTime]::UtcNow.ToString('o');customer=@{name=$name;phone=$phone;address=$address};items=$items;subtotal=$subtotal;shipping=$shipping;total=($subtotal+$shipping);delivery=$Payload.delivery;payment=$Payload.payment;paymentStatus=$(if($Payload.payment -eq 'demo'){'simulated'}else{'unpaid'});status='new'}
        foreach($line in $items){($script:db.books | Where-Object id -eq $line.id).stock-=$line.quantity}
        $script:db.orders=@($script:db.orders)+$order;Save-Database
        return (Reply 201 @{order=(Public-Order $order);receiptToken=$order.receiptToken})
    }
    if ($Path -match '^/api/orders/(KZ-[A-F0-9]{12})$' -and $Method -eq 'GET') {
        $order=$script:db.orders | Where-Object id -eq $Matches[1] | Select-Object -First 1
        if(-not $order -or (-not $isAdmin -and $Headers['x-order-token'] -cne $order.receiptToken)){return (Fail 'Buyurtma topilmadi' 404)}
        return (Reply 200 @{order=(Public-Order $order)})
    }
    if($Path.StartsWith('/api/admin/')){
        if(-not $isAdmin){return (Fail 'Admin sifatida kiring' 401)}
        if($Path -eq '/api/admin/data' -and $Method -eq 'GET'){return (Reply 200 @{books=@($script:db.books);reviews=@($script:db.reviews);orders=@($script:db.orders | ForEach-Object {Public-Order $_})})}
        if(($Path -eq '/api/admin/books' -and $Method -eq 'POST') -or ($Path -match '^/api/admin/books/(\d+)$' -and $Method -eq 'PUT')){
            $editId=if($Method -eq 'PUT'){[long]($Path.Split('/')[-1])}else{0}
            $title=Text-Field $Payload.title 2 120;$author=Text-Field $Payload.author 2 100;$description=Text-Field $Payload.description 10 2000
            $price=Whole-Number $Payload.price 1000 10000000;$stock=Whole-Number $Payload.stock 0 10000
            if($Payload.category -notin @('Adabiyot','Rivojlanish','Bolalar')){return (Fail 'Invalid category')}
            if([string]$Payload.color -notmatch '^#[a-fA-F0-9]{6}$'){return (Fail 'Invalid color')}
            $tag=([string]$Payload.tag).Trim();if($tag.Length -gt 40){return (Fail 'Tag too long')}
            if($editId){$book=$script:db.books | Where-Object id -eq $editId | Select-Object -First 1;if(-not $book){return (Fail 'Kitob topilmadi' 404)}}
            else{$nextId=1+($script:db.books | Measure-Object -Property id -Maximum).Maximum;$book=[pscustomobject]@{id=$nextId;title='';author='';description='';price=0;stock=0;category='';color='';paper='#fff0c7';symbol='*';tag='';archived=$false};$script:db.books=@($script:db.books)+$book}
            $book.title=$title;$book.author=$author;$book.description=$description;$book.price=$price;$book.stock=$stock;$book.category=$Payload.category;$book.color=$Payload.color;$book.tag=$tag
            Save-Database;return (Reply 200 @{book=$book})
        }
        if($Path -match '^/api/admin/books/(\d+)/archive$' -and $Method -eq 'PUT'){
            $book=$script:db.books | Where-Object id -eq ([long]$Matches[1]) | Select-Object -First 1
            if(-not $book){return (Fail 'Kitob topilmadi' 404)};$book.archived=-not $book.archived;Save-Database;return (Reply 200 @{ok=$true})
        }
        if($Path -match '^/api/admin/reviews/([a-f0-9]{32})$' -and $Method -eq 'PUT'){
            $review=$script:db.reviews | Where-Object id -eq $Matches[1] | Select-Object -First 1
            if(-not $review){return (Fail 'Sharh topilmadi' 404)}
            if($Payload.status -notin @('approved','rejected')){return (Fail 'Invalid review status')}
            $review.status=$Payload.status;Save-Database;return (Reply 200 @{ok=$true})
        }
        if($Path -match '^/api/admin/orders/(KZ-[A-F0-9]{12})$' -and $Method -eq 'PUT'){
            $order=$script:db.orders | Where-Object id -eq $Matches[1] | Select-Object -First 1
            if(-not $order){return (Fail 'Buyurtma topilmadi' 404)}
            $transitions=@{new=@('confirmed','cancelled');confirmed=@('shipped','cancelled');shipped=@('completed');completed=@();cancelled=@()}
            if($Payload.status -notin $transitions[$order.status]){return (Fail 'Bu holatga otish mumkin emas' 409)}
            if($Payload.status -eq 'cancelled'){foreach($line in $order.items){($script:db.books | Where-Object id -eq $line.id).stock+=$line.quantity}}
            $order.status=$Payload.status;Save-Database;return (Reply 200 @{ok=$true})
        }
    }
    return (Fail 'Endpoint topilmadi' 404)
}
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$Port);$listener.Start()
Write-Output "Kitobzor: http://localhost:$Port"
try{
    while($true){
        $client=$listener.AcceptTcpClient()
        try{
            $client.ReceiveTimeout=5000;$client.SendTimeout=5000;$stream=$client.GetStream();$headerBytes=[Collections.Generic.List[byte]]::new()
            while($true){$b=$stream.ReadByte();if($b -lt 0){throw 'Disconnected'};$headerBytes.Add([byte]$b);$n=$headerBytes.Count;if($n -gt 16384){throw 'Header too large'};if($n -ge 4 -and $headerBytes[$n-4] -eq 13 -and $headerBytes[$n-3] -eq 10 -and $headerBytes[$n-2] -eq 13 -and $headerBytes[$n-1] -eq 10){break}}
            $lines=[Text.Encoding]::ASCII.GetString($headerBytes.ToArray()).Split(@("`r`n"),[StringSplitOptions]::None);$parts=$lines[0].Split(' ');$method=$parts[0];$path=($parts[1] -split '\?')[0];$headers=@{}
            foreach($line in $lines | Select-Object -Skip 1){if($line.Contains(':')){$kv=$line -split ':',2;$headers[$kv[0].ToLowerInvariant()]=$kv[1].Trim()}}
            $length=0;if($headers['content-length']){$length=Whole-Number $headers['content-length'] 0 131072}
            $bytes=New-Object byte[] $length;$offset=0
            while($offset -lt $length){$read=$stream.Read($bytes,$offset,$length-$offset);if($read -le 0){throw 'Disconnected body'};$offset+=$read}
            if($path.StartsWith('/api/')){
                try{$payload=@{};if($length){$payload=$utf8.GetString($bytes)|ConvertFrom-Json};$response=Handle-Api $method $path $headers $payload}
                catch{[IO.File]::AppendAllText((Join-Path $dataRoot 'api-errors.log'),($_.Exception.Message+[Environment]::NewLine),$utf8);$response=Fail 'Malumotlarni tekshiring va qayta urinib koring' 400}
                $body=$utf8.GetBytes($response.body)
            }else{
                $allowed=@{'/'=@('index.html','text/html; charset=utf-8');'/index.html'=@('index.html','text/html; charset=utf-8');'/style.css'=@('style.css','text/css; charset=utf-8');'/storefront.js'=@('storefront.js','application/javascript; charset=utf-8')}
                if($method -notin @('GET','HEAD')){$response=Fail 'Method not allowed' 405;$body=$utf8.GetBytes($response.body)}
                elseif($allowed.ContainsKey($path)){$response=@{status=200;type=$allowed[$path][1]};$body=[IO.File]::ReadAllBytes((Join-Path $webRoot $allowed[$path][0]))}
                else{$response=Fail 'Sahifa topilmadi' 404;$body=$utf8.GetBytes($response.body)}
            }
            $reason=@{200='OK';201='Created';400='Bad Request';401='Unauthorized';403='Forbidden';404='Not Found';405='Method Not Allowed';409='Conflict';429='Too Many Requests'};$cookieHeader=''
            if($response.cookie){$cookieHeader="Set-Cookie: $($response.cookie)`r`n"}
            $head=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $($response.status) $($reason[$response.status])`r`nContent-Type: $($response.type)`r`nContent-Length: $($body.Length)`r`nConnection: close`r`nCache-Control: no-store`r`nX-Content-Type-Options: nosniff`r`nReferrer-Policy: same-origin`r`n$cookieHeader`r`n")
            $stream.Write($head,0,$head.Length);if($method -ne 'HEAD'){$stream.Write($body,0,$body.Length)};$stream.Flush()
        }catch{
            [IO.File]::AppendAllText((Join-Path $PSScriptRoot 'server-error.log'), ($_.Exception.Message + [Environment]::NewLine), $utf8)
        }finally{$client.Dispose()}
    }
}finally{$listener.Stop()}
