# SimpleCryptoMixin
#
# Rails mix-in implementing get_ and set_password methods that
# decrypt/encrypt a plain text password from/to an
# "encrypted_password" attribute.
#
# The class into which this module is mixed must have these
# attributes: "encrypted_password", and "salt".
#
module SimpleCryptoMixin

  # Decrypt "encrypted_password" attribute with a key. Raise
  # OpenSSL::CipherError if key is incorrect.
  def get_password key
    encrypted = self.encrypted_password
    if encrypted.blank?
      nil
    else
      c = get_crypto key
      c.decrypt self.encrypted_password, get_salt
    end
  end

  # Encrypt a plain-text password into attribute "encrypted_password"
  # with a key.
  def set_password key, pw
    unless pw.blank?
      c = get_crypto key
      self.encrypted_password = c.encrypt pw, get_salt
    end
  end
  
  protected
  
  def get_crypto key
    SimpleCrypto.new key
  end

  def get_salt
    self.salt ||= SimpleCrypto.new_salt
  end
end
