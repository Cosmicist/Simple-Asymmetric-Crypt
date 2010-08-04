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
    
    public function __construct() {}

    public function createKeyPair( $key_filename, $passphrase = "", $bits = 1024 )
    {
        $config = array(
            'private_key_type' =>  OPENSSL_KEYTYPE_RSA, // As of php 5.3 it only supports RSA keys creation
            'private_key_bits' => $bits
        );
        $pkey = openssl_pkey_new( $config );
        if( ! $pkey )
            throw new Exception("Couldn't create private key!");
        
        if( ! openssl_pkey_export_to_file( $pkey, "$key_filename.key", $passphrase ) )
            throw new Exception("Couldn't save private key to file!");
        
        // Get public key from private key
        $key_details = openssl_pkey_get_details( $pkey );
        if( ! file_put_contents("$key_filename.pub", $key_details['key']) )
            throw new Exception("Couldn't save public key to file!");
    }

    public function setBase64Usage( $use, $chunk_split = FALSE )
    {
        $this->_base64 = $use;
        $this->_csplit = $chunk_split;
    }

    public function setPublicKey( $pub_key_file )
    {
        if( ! file_exists( $pub_key_file ) ) 
            throw new Exception("The public key file ('$pub_key_file') specified doesn't exist!");
        
        $this->_pub_key = openssl_pkey_get_public( file_get_contents( $pub_key_file ) );

        if( ! $this->_pub_key )
            throw new Exception("Failed to prepare the public key, make sure the file is the correct one.");
    }

    public function setPrivateKey( $priv_key_file, $passphrase = "" )
    {
        if( ! file_exists( $priv_key_file ) ) 
            throw new Exception("The private key file ('$priv_key_file') specified doesn't exist!");
        
        $this->_priv_key = openssl_pkey_get_private( file_get_contents( $priv_key_file ), $passphrase );
        
        if( ! $this->_priv_key )
            throw new Exception("Failed to prepare the private key, make sure the file and passphrase are correct.");
    }
    
    /**
     * Encrypts data using a public key
     * 
     * @param $data Data to be encrypted
     * @param $base64 Encode result in base64
     * @return $string Encrypted data
     */
    public function encrypt( $data, $base64 = TRUE, $chunk_split = TRUE )
    {
        if( ! $this->_pub_key )
            throw new Exception("No Public Key!");
        
        openssl_public_encrypt( $data, $out, $this->_pub_key );
        
        if( $base64 )
        {
            $out = base64_encode( $out );
            if( $chunk_split ) $out = chunk_split( $out );
        }
        
        return $out;
    }
    
    /**
     * Decrypts data using a public key
     * 
     * @param $data Encrypted data
     * @param $base64 Tell if the data is base64 encoded
     * @return $string Decrypted data
     */
    public function decrypt( $data, $base64 = TRUE )
    {
        if( ! $this->_priv_key )
            throw new Exception("No Private Key!");
       
        if( $base64 ) $data = base64_decode( $data );
        
        openssl_private_decrypt( $data, $out, $this->_priv_key  );
        
        return $out;
    }
}
