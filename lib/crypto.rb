require 'openssl'
require 'digest/sha2'

# Code from http://tinyurl.com/43zvt4 modified so that a Crypto instance is
# created with a salt and that instance is used to encrypt and decrypt. The
# salt is unique for each encryption & decryption session.
#
# A salt can be created with Internaut Design's easy algorithm:
#   DateTime.now.hash.abs.to_s(36)
#
class Crypto
  KEY = "3efb989671ff4f48e22152660a49b18c"
  
  def self.new_salt
    DateTime.now.hash.abs.to_s(36)
  end
  
  def initialize(salt='')
    @salt = salt
  end
  
  def encrypt(plain_text)
    crypto = start(:encrypt)
    
    cipher_text = crypto.update(plain_text)
    cipher_text << crypto.final
    
    cipher_hex = cipher_text.unpack("H*").join
    
    return cipher_hex
  end
  
  def decrypt(cipher_hex)
    crypto = start(:decrypt)
    
    cipher_text = cipher_hex.gsub(/(..)/){|h| h.hex.chr}
    
    plain_text = crypto.update(cipher_text)
    plain_text << crypto.final
    
    return plain_text
  end
  
  protected
  
  def start(mode)
    crypto = OpenSSL::Cipher::Cipher.new('aes-256-ecb').send(mode)
    crypto.key = Digest::SHA256.hexdigest(KEY + @salt)
    return crypto
  end
end
