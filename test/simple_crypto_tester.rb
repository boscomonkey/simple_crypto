#!/usr/bin/env ruby

require 'test/unit'
require File.join(File.expand_path(File.dirname(__FILE__)),
                  "..", "lib", "simple_crypto")

class SimpleCryptoTester < Test::Unit::TestCase
  KEY = 'a test key'
  SALT = 'some salt value'

  def setup
    @crypto = SimpleCrypto.new KEY
  end

  def test_new_crypto
    assert_not_nil @crypto
  end

  def test_new_crypto_no_key
    assert_raise ArgumentError do
      another_crypto = SimpleCrypto.new
    end
  end

  def test_encrypt_decrypt
    orig = 'original text'
    hex = @crypto.encrypt orig

    assert_not_nil hex
    assert_not_equal orig, hex

    decrypted = @crypto.decrypt hex
    assert_equal decrypted, orig

    assert_raise OpenSSL::CipherError do
     @crypto.decrypt hex, SALT
    end

    another_crypto = SimpleCrypto.new 'another key'
    assert_raise OpenSSL::CipherError do
      another_crypto.decrypt hex
    end
  end

  def test_encrypt_decrypt_with_salt
    orig = 'original text'
    hex = @crypto.encrypt orig, SALT

    assert_not_nil hex
    assert_operator hex.length, :>, orig.length

    decrypted = @crypto.decrypt hex, SALT
    assert_equal decrypted, orig

    assert_raise OpenSSL::CipherError do
      @crypto.decrypt hex
    end
  end
end
