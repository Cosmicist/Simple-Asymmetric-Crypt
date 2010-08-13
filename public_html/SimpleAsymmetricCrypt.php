<?php
/*
 * Copyright (c) 2010 Luciano Longo
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

class SimpleAsymmetricCrypt
{
    private $_pub_key;
    private $_priv_key;
    private $_base64 = TRUE;
    private $_csplit = FALSE;
    private $_b64_url_safe = FALSE;
    private $_priv_key_ext;
    private $_pub_key_ext;
    
    public function __construct( $pri_key_ext = '.key', $pub_key_ext = '.pub' )
    {
        $this->_priv_key_ext = $pri_key_ext;
        $this->_pub_key_ext = $pub_key_ext;
    }

    /**
     * Creates a key pair (private and public) and saves it to a file
     *
     * The $filename shouldn't have an extension, as it will be appended one
     * as defined upon instantiation.
     *
     * @param string $filename
     * @param string $passphrase
     * @param int $bits
     * @return bool
     */
    public function createKeyFiles( $filename, $passphrase, $bits = 1024 )
    {
        // Create key
        $key = $this->createKey( $passphrase, $bits );

        // Save Private Key to file
        if( ! file_put_contents( "$filename.key", $key['private'] ) )
            throw new Exception( "Couldn't save Private Key to file!");

        // Save Public Key to file
        if( ! file_put_contents( "$filename.pub", $key['public']) )
            throw new Exception( "Couldn't save Public Key to file!");
        
        return TRUE;
    }

    /**
     * Creates a Private Key and it's derivative Public Key
     *
     * It returns an array with the 'private' and 'public'
     * array keys holding it's respective keys.
     *
     * @param string $passphrase
     * @param int $bits (>= 384)
     * @return array
     */
    public function createKey( $passphrase, $bits = 1024 )
    {
        // Make sure is an int
        $bits = (int)$bits;

        // Check size
        if( $bits < 384 )
            throw new Exception("The bits can't be less than 384!");

        // Create Private Key
        if( ! ( $pkey = openssl_pkey_new(array(
            'private_key_type' =>  OPENSSL_KEYTYPE_RSA, // As of 5.3, php only supports RSA keys creation
            'private_key_bits' => $bits
        )))) throw new Exception("Couldn't create private key!");

        // Get key details
        $key_details = openssl_pkey_get_details( $pkey );
        
        if( ! openssl_pkey_export($pkey, $pkey_out) )
            throw new Exception("Couldn't export private key!");

        $key['private'] = $pkey_out;
        $key['public'] = $key_details['key'];

        return $key;
    }

    /**
     * Get the Public Key of a Private Key as a string
     *
     * @return string
     */
    public function getPublicKey()
    {
        if( ! $this->_priv_key )
            throw new Exception("Set a Private Key first!");
        
        // Get key details
        if( ! ( $details = openssl_pkey_get_details( $this->_priv_key ) ) )
            return false;
        
        // Return derived Public Key
        return $details['key'];
    }


    /**
     * Tell the class whether to use base64 when encrypting and decrypting
     *
     * @param bool $apply
     * @param bool $chunk_split
     * @return void
     */
    public function useBase64( $use, $chunk_split = FALSE )
    {
        $this->_base64 = $use;
        $this->_csplit = $chunk_split;
    }

    /**
     * Set a public key to use for encryption
     *
     * @param string $pub_key Can be a filename or the public key string itself
     */
    public function setPublicKey( $pub_key )
    {
        if( file_exists( $pub_key ) )
        {
            if( ! is_readable( $pub_key ) )
                throw new Exception("The public key file ('$pub_key') isn't readable!");
            
            $pub_key = file_get_contents( $pub_key );
        }
        
        $this->_pub_key = openssl_pkey_get_public( $pub_key );
        
        if( ! $this->_pub_key )
            throw new Exception("Failed to prepare the public key!");
    }

    /**
     * Set a private key to use for encryption
     *
     * @param string $priv_key Can be a filename or the private key string itself
     * @param string $passphrase
     */
    public function setPrivateKey( $priv_key, $passphrase )
    {
        if( file_exists( $priv_key ) )
        {
            if( ! is_readable( $priv_key ) )
                throw new Exception("The private key file ('$pub_key') isn't readable!");
            
            $priv_key = file_get_contents( $priv_key );
        }
        
        $this->_priv_key = openssl_pkey_get_private( $priv_key, $passphrase );

        if( ! $this->_priv_key )
            throw new Exception("Failed to prepare the private key!");
    }
    
    /**
     * Encrypts data using a public key
     * 
     * @param $data Data to be encrypted
     * @param $base64 Encode result in base64
     * @return $string Encrypted data
     */
    public function encrypt( $data, $url_safe = FALSE )
    {
        if( ! $this->_pub_key )
            throw new Exception("No Public Key!");
        
        openssl_public_encrypt( $data, $out, $this->_pub_key );
        
        if( $this->_base64 || $url_safe )
        {
            $out = base64_encode( $out );
            if( $url_safe ) $out = strtr($out, '+/=', '-_,');
            if( $this->_csplit ) $out = chunk_split( $out );
        }
        
        return $out;
    }
    
    /**
     * Decrypts data using a private key
     * 
     * @param $data Encrypted data
     * @param $base64 Tell if the data is base64 encoded
     * @return $string Decrypted data
     */
    public function decrypt( $data, $url_safe = FALSE )
    {
        if( ! $this->_priv_key )
            throw new Exception("No Private Key!");
       
        if( $this->_base64 || $url_safe )
        {
            if( $url_safe ) $data = strtr( $data, '-_,', '+/=');
            $data = base64_decode( $data );
        }
        
        openssl_private_decrypt( $data, $out, $this->_priv_key  );
        
        return $out;
    }
}
