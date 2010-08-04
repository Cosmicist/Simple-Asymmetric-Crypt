<?php

error_reporting( E_ALL ^ E_NOTICE );

require "crypto.php";
$c = new SimpleAsymmetricCrypt();

define('IS_AJAX', strtolower( $_SERVER['HTTP_X_REQUESTED_WITH'] ) == 'xmlhttprequest');

if( isset( $_GET['key'] ) && IS_AJAX )
{
    if( ! preg_match( '/^[a-z0-9_-]+$/i', $_GET['key'] ) )
        sendAjaxError('Invalid key name!', 'error');
    
    $keyfile = '../keys/' . $_GET['key']. '.pub';
    
    if( ! file_exists( $keyfile ) )
        sendAjaxError("The key doesn't exist!", 'error');
    
    sendAjaxResponse( file_get_contents( $keyfile ) );
}

if( $_SERVER['REQUEST_METHOD'] == 'POST' && isset( $_POST['action'] ) )
{
    $action = $_POST['action'];
    $data = $_POST['data'];

    if( ( $action == 'Encrypt' || $action == 'Decrypt' ) && ! preg_match( '/^[a-z0-9_-]+$/i', $_POST['key'] ) )
        exit("Invalid key name!");

    $key = $_POST['key'];
    if( $key )
    {
        $pub_key = "../keys/$key.pub";
        $priv_key = "../keys/$key.key";
    }

    $pass = $_POST['pass'];

    switch( $_POST['action'] )
    {
        case 'Create key':
            $create_msg->type = 'success';
            $create_msg->text = 'Key pair successfully created!';
            try
            {
                $c->createKeyPair( '../keys/' . $_POST['key_name'], $_POST['key_pass'], (int)$_POST['key_bits'] );
                
                if( IS_AJAX ) sendAjaxResponse( $create_msg->text, 'success' );
            } catch( Exception $e ) {
                $create_msg_type = "error";
                $create_error = $e->getMessage();
                
                if( IS_AJAX ) sendAjaxError( $create_msg->text );
            }
        break;

        case 'Encrypt':
            $c->setPublicKey( $pub_key );
            $result = $c->encrypt( $data );
            
            if( IS_AJAX ) sendAjaxResponse( $result );
        break;
        
        case 'Decrypt':
            $result = $_POST['encrypted'];
            $c->setPrivateKey( $priv_key, $pass);
            $dec_result = $c->decrypt( $result );
            
            if( IS_AJAX ) sendAjaxResponse( $dec_result );
        break;
    }
}

function sendAjaxError( $text )
{
    sendAjaxResponse( $text, 'error' );
}

function sendAjaxResponse( $text, $status = 'success' )
{
    $r->text = $text;
    $r->status = $status;
    
    exit( json_encode( $r ) );
}

// List available keys
$dir = opendir('../keys');
while( $f = readdir( $dir ) )
{
    if( $f == '.' || $f == '..' || ! preg_match('/\.key$/i', $f) ) continue;
    $f = explode('.', $f);

    if( $f[1] != 'key' ) continue;
    $selected = $f[0] == $key ? ' selected="selected"' : '';
    $keys .= "<option value=\"{$f[0]}\"$selected>{$f[0]}</option>";
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>Asymmetric key algorythms (using OpenSSL)</title>
    <link rel="stylesheet" href="http://www.blueprintcss.org/blueprint/screen.css"/>
    <style>
    textarea { width: 420px; height: 180px; }
    select { padding: 5px; width: 300px; }
    pre, code, tt {
        background: #eee;
        padding: 5px;
        -moz-border-radius: 3px;
        text-shadow: 1px 1px 5px #666;
    }
    #create-key-message { display: none; }
    </style>
    <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>
</head>
<body>

    <div class="container">
        <hr class="space"/>
        <h1>Asymmetric key algorythms (using OpenSSL)</h1>
        <hr class="space"/>
        
        <div class="span-12">
        <form method="post" id="create_key_form">
            
            <fieldset>
                <legend>Create a key pair</legend>

                <?php if( $create_msg ) : ?>
                    <div class="<?=$create_msg->type?>"><?=$create_msg->text?></div>
                <?php endif; ?>
                
                <div id="create-key-message"></div>

                <p>
                    <label for="key_name">Key name</label><br/>
                    <input type="text" id="key_name" name="key_name" value="test_key" class="text"/><br/>
                    <em>The private and public keys will be named the same, but the public will have a <code>.pub</code> extension</em>
                </p>

                <p>
                    <label for="key_pass">Passphrase</label><br/>
                    <input type="password" id="key_pass" name="key_pass" class="text"/><br/>
                </p>

                <p>
                    <label for="key_bits">Bits</label><br/>
                    <input type="text" id="key_bits" name="key_bits" value="1024" class="text"/><br/>
                </p>
                
                <p>
                    <input type="submit" name="action" value="Create key"/>
                </p>
            </fieldset>

            <fieldset>
                <legend>To keep in mind...</legend>
                <p>
                    <a href="http://en.wikipedia.org/wiki/Public-key_cryptography"><strong>Public-key cryptography</strong></a>
                </p>
                
                <hr/>
                
                <p>
                    <strong>GET content-length:</strong>
                </p>
                <p>
                    Apparently there is no fixed max size, but any URL length below 1024 characters should be safe enough for the vast majority of browsers and SGML compatible, less that 2000 if the url is not going to be used in a link tag (&lt;a href="{url}"&gt;).
                </p>
                <p>
                    Source: <a href="http://classicasp.aspfaq.com/forms/what-is-the-limit-on-querystring/get/url-parameters.html">What is the limit on QueryString / GET / URL parameters?</a></p>
                </p>
                
                <hr/>
                
                <p>
                    <strong>Size of data to encrypt:</strong> <a href="http://php.net/openssl_public_encrypt#55901">Thomas Horsten comment on php.net site</a>
                </p>
                <p>[...]</p>
                <p>Basically when you encrypt something using an RSA key (whether public or private), the encrypted value must be smaller than the key (due to the maths used to do the actual encryption). So if you have a 1024-bit key, in theory you could encrypt any 1023-bit value (or a 1024-bit value smaller than the key) with that key.</p>

                <p>However, the PKCS#1 standard, which OpenSSL uses, specifies a padding scheme (so you can encrypt smaller quantities without losing security), and that padding scheme takes a minimum of 11 bytes (it will be longer if the value you're encrypting is smaller). So <strong>the highest number of bits you can encrypt with a 1024-bit key is 936 bits</strong> because of this (unless you disable the padding by adding the OPENSSL_NO_PADDING flag, in which case you can go up to 1023-1024 bits). <strong>With a 2048-bit key it's 1960 bits instead.</strong></p>

                <p>But as chsnyder correctly wrote, the normal application of a public key encryption algorithm is to store a key or a hash of the data you want to respectively encrypt or sign. A hash is typically 128-256 bits (the PHP sha1() function returns a 160 bit hash). And an AES key is 128 to 256 bits. So either of those will comfortably fit inside a single RSA encryption.</p>
            </fieldset>
        </form>
        </div>

        <div class="span-12 last">
        <form method="post" id="form2"> 

        <fieldset>
            <legend>Available keys</legend>
            
            <p>
                <label for="keys">Choose a key pair to use</label><br/>
                <select id="keys" name="key">
                    <?=$keys?>
                </select><br/>
                <em>Test keys passphrase: <code>asdasd</code></em>
            </p>
            
            <p><pre id="pub-key"></pre></p>

            <p>
                <label>Enter passphrase for key</label> (optional)<br/>
                Enter the passphrase for the key if you are attemping a decryption.<br/>
                <input type="password" id="pass" name="pass" class="text" value="<?=$pass?>"/>
            </p>
        </fieldset>

        <fieldset>
            <legend>Data encryption/decryption</legend>
            
            <p>
                <label for="data">Enter a message to be encrypted</label><br/>
                The data is encrypted with the <code>public key</code>, this key can be distributed without any danger, because it's only used to encrypt data, <strong>NOT</strong> to decrypt it.<br/>
                <textarea id="data" name="data"><?=$data?></textarea>
            </p>
            <p>
                <input type="submit" name="action" value="Encrypt"/>
            </p>
            
            <hr/>
            
            <p>
                <label for="encrypted">Encrypted message</label><br/>
                The encrypted data can only be decrypted with the <code>private key</code>. This key MUST be kept in a secure place an it should be available only to the entity in charge of receiving encrypted data. It shouldn't be distributed at all.<br/>
                <textarea id="encrypted" name="encrypted"><?=$result?></textarea>
            </p>
            <p>
                <input type="submit" name="action" value="Decrypt"/>
            </p>
            
            <p>
                <label>Decrypted result:</label><br/>
                <pre id="dec-result"><?=$dec_result?></pre>
            </p>
        </fieldset>

        </form>
        </div>
    </div>
    
    <script>
    (function($)
    {
        $(function()
        {
            showPubKey();
            $('#keys').change(showPubKey);
            
            $('form').submit(function(e)
            {
                e.preventDefault();
                
                var action = e.originalEvent.explicitOriginalTarget.value;
                var post_data = $(this).serialize() + '&action='+action;
                
                $.post('.', post_data, function( data )
                {
                    switch( action )
                    {
                        case 'Create key':
                            $('#create-key-message').html(data.text).addClass(data.status).show('fast');
                            if( data.status == 'success' )
                            {
                                var key_name = $('#key_name').val();
                                $('#keys').append('<option value="'+key_name+'" selected="selected">'+key_name+'</option>');
                                showPubKey();
                            }
                        break;
                        
                        case 'Encrypt':
                            $('#encrypted').addClass(data.status).val( data.text );
                        break;
                        
                        case 'Decrypt':
                            $('#dec-result').addClass(data.status).html( data.text );
                        break;
                    }
                    
                }, 'json');
            });
        });
        
        function showPubKey()
        {
            var pre = $('#pub-key').removeClass('error');
            
            var key_name = $('#keys').val();
            $.getJSON('?key='+key_name, function( data, textStatus )
            {
                pre.addClass(data.status).html( data.text );
            });
        }
    })(jQuery);
    </script>
</body>
</html>
