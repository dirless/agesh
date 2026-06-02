require "../spec_helper"

describe AgeSh::Crypto::SessionKey do
  it "derives the same key from the same inputs" do
    shared_secret = Random::Secure.random_bytes(32)
    client_pub = Random::Secure.random_bytes(32)
    server_pub = Random::Secure.random_bytes(32)

    key1 = AgeSh::Crypto::SessionKey.derive(shared_secret, client_pub, server_pub)
    key2 = AgeSh::Crypto::SessionKey.derive(shared_secret, client_pub, server_pub)
    key1.should eq(key2)
    key1.size.should eq(32)
  end

  it "derives different keys for different shared secrets" do
    client_pub = Random::Secure.random_bytes(32)
    server_pub = Random::Secure.random_bytes(32)

    key1 = AgeSh::Crypto::SessionKey.derive(Random::Secure.random_bytes(32), client_pub, server_pub)
    key2 = AgeSh::Crypto::SessionKey.derive(Random::Secure.random_bytes(32), client_pub, server_pub)
    key1.should_not eq(key2)
  end

  it "derives different keys when client/server pubs are swapped" do
    shared_secret = Random::Secure.random_bytes(32)
    client_pub = Random::Secure.random_bytes(32)
    server_pub = Random::Secure.random_bytes(32)

    key_ab = AgeSh::Crypto::SessionKey.derive(shared_secret, client_pub, server_pub)
    key_ba = AgeSh::Crypto::SessionKey.derive(shared_secret, server_pub, client_pub)
    key_ab.should_not eq(key_ba)
  end

  it "raises on wrong input sizes" do
    shared = Random::Secure.random_bytes(32)
    client_pub = Random::Secure.random_bytes(32)
    server_pub = Random::Secure.random_bytes(32)

    expect_raises(AgeSh::Error) do
      AgeSh::Crypto::SessionKey.derive(Bytes.new(16), client_pub, server_pub)
    end

    expect_raises(AgeSh::Error) do
      AgeSh::Crypto::SessionKey.derive(shared, Bytes.new(16), server_pub)
    end

    expect_raises(AgeSh::Error) do
      AgeSh::Crypto::SessionKey.derive(shared, client_pub, Bytes.new(16))
    end
  end
end
