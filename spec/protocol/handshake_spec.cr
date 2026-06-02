require "../spec_helper"

describe AgeSh::Handshake do
  it "derives matching transport keys on both sides" do
    client_priv, client_pub = Age::X25519.generate_keypair
    server_priv, server_pub = Age::X25519.generate_keypair

    client_shared = Age::X25519.shared_secret(client_priv, server_pub)
    server_shared = Age::X25519.shared_secret(server_priv, client_pub)
    client_shared.should eq(server_shared)

    client_key = AgeSh::Crypto::SessionKey.derive(client_shared, client_pub, server_pub)
    server_key = AgeSh::Crypto::SessionKey.derive(server_shared, client_pub, server_pub)
    client_key.should eq(server_key)
  end

  it "creates compatible transport sessions for client and server" do
    transport_key = Random::Secure.random_bytes(32)
    client = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
    server = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

    # Client -> Server
    record = client.send_record(AgeSh::Constants::TAG_DATA, "hello".to_slice)
    tag, payload = server.recv_record(record)
    tag.should eq(AgeSh::Constants::TAG_DATA)
    String.new(payload).should eq("hello")

    # Server -> Client
    record = server.send_record(AgeSh::Constants::TAG_DATA, "world".to_slice)
    tag, payload = client.recv_record(record)
    tag.should eq(AgeSh::Constants::TAG_DATA)
    String.new(payload).should eq("world")
  end
end
