require 'openssl'
require 'digest/sha2'

# This code is derived from Robert Sosinski's "Simple and Restful
# Account Recovery for Ruby on Rails" - http://tinyurl.com/43zvt4
#
# Create a new SimpleCrypto object with a key:
#       crypto = SimpleCrypto.new 'some random key'
#
# Encrypt a string (i.e., password) into a hex string
#       enc_hex = crypto.encrypt 'a secret password'
#       # => "71a7343283d61656973ba8923bde22e92b6ed2078da390ab422d8f2377836173"
#
# Decrypt said hex string back into the original string
#       orig = crypto.decrypt enc_hex
#
# Add a salt so that the same password doesn't encrypt to the same hex string
#       salt = SimpleCrypto.new_salt
#       hex2 = crypto.encrypt 'a secret password', salt
#       # => "b14672abb69d077fe43cf57c47b54b448088c782fec4198c2c3548aa8d587b73"
#
# Pass the salt to decrypt to get the same string back
#       orig = crypto.decrypt hex2, salt
# 
class SimpleCrypto
  def self.new_salt
    # from Internaut Design's blog
    Time.now.hash.abs.to_s(36)
  end
  
  def initialize(key)
    @key = key
  end
  
  def encrypt(plain_text, salt='')
    crypto = start(:encrypt, salt)
    
    cipher_text = crypto.update(plain_text)
    cipher_text << crypto.final
    
    cipher_hex = cipher_text.unpack("H*").join
  end
  
  def decrypt(cipher_hex, salt='')
    crypto = start(:decrypt, salt)
    
    cipher_text = cipher_hex.gsub(/(..)/){|h| h.hex.chr}
    
    plain_text = crypto.update(cipher_text)
    plain_text << crypto.final
  end
  
  protected
  
  def start(mode, salt)
    crypto = OpenSSL::Cipher::Cipher.new('aes-256-ecb').send(mode)
    crypto.key = Digest::SHA256.hexdigest(@key + salt)
    crypto
  end
end
