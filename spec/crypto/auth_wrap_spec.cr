require "../spec_helper"

describe AgeSh::Crypto::AuthWrap do
  it "wraps and unwraps a challenge" do
    keypair = Age.keygen
    challenge = Random::Secure.random_bytes(32)

    _, recipient_pub_bytes = Age::Bech32.decode(keypair.public_key.value)
    _, secret_key_bytes = Age::Bech32.decode(keypair.secret_key.value.downcase)

    ephem_pub, wrapped = AgeSh::Crypto::AuthWrap.wrap(challenge, recipient_pub_bytes)
    ephem_pub.size.should eq(32)
    wrapped.size.should eq(48) # 32 + 16 tag

    recovered = AgeSh::Crypto::AuthWrap.unwrap(ephem_pub, wrapped, secret_key_bytes)
    recovered.should eq(challenge)
  end

  it "fails to unwrap with wrong secret key" do
    keypair = Age.keygen
    wrong_keypair = Age.keygen
    challenge = Random::Secure.random_bytes(32)

    _, recipient_pub_bytes = Age::Bech32.decode(keypair.public_key.value)
    _, wrong_sec_bytes = Age::Bech32.decode(wrong_keypair.secret_key.value.downcase)

    ephem_pub, wrapped = AgeSh::Crypto::AuthWrap.wrap(challenge, recipient_pub_bytes)

    expect_raises(Age::Error) do
      AgeSh::Crypto::AuthWrap.unwrap(ephem_pub, wrapped, wrong_sec_bytes)
    end
  end

  it "produces different wrapped values each time" do
    keypair = Age.keygen
    challenge = Random::Secure.random_bytes(32)

    _, recipient_pub_bytes = Age::Bech32.decode(keypair.public_key.value)

    _, wrapped1 = AgeSh::Crypto::AuthWrap.wrap(challenge, recipient_pub_bytes)
    _, wrapped2 = AgeSh::Crypto::AuthWrap.wrap(challenge, recipient_pub_bytes)
    wrapped1.should_not eq(wrapped2) # different ephemeral key each time
  end
end
