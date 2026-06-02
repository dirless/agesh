require "../spec_helper"

# Helper: simulate one leg of the protocol (write to buf, read back).
def transfer(data : Bytes) : Bytes
  buf = IO::Memory.new
  AgeSh::Framer.write_message(buf, data)
  buf.rewind
  AgeSh::Framer.read_message(buf)
end

describe AgeSh::Authentication do
  it "completes a full auth flow" do
    keypair = Age.keygen
    _, pub_bytes = Age::Bech32.decode(keypair.public_key.value)
    _, sec_bytes = Age::Bech32.decode(keypair.secret_key.value.downcase)

    transport_key = Random::Secure.random_bytes(32)
    client_transport = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
    server_transport = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

    # === Client sends AUTH_REQUEST -> Server reads it ===
    request = AgeSh::Messages.write_auth_request("testuser", keypair.public_key.value)
    encrypted_request = client_transport.send_record(AgeSh::Constants::TAG_DATA, request)
    server_received = transfer(encrypted_request)
    _, request_data = server_transport.recv_record(server_received)
    username, pubkey_str = AgeSh::Messages.read_auth_request(request_data)
    username.should eq("testuser")
    pubkey_str.should eq(keypair.public_key.value)

    # === Server wraps challenge, sends AUTH_CHALLENGE -> Client reads it ===
    challenge = Random::Secure.random_bytes(AgeSh::Constants::CHALLENGE_SIZE)
    ephemeral_pub, wrapped = AgeSh::Crypto::AuthWrap.wrap(challenge, pub_bytes)
    challenge_msg = AgeSh::Messages.write_auth_challenge(challenge, ephemeral_pub, wrapped)
    encrypted_challenge = server_transport.send_record(AgeSh::Constants::TAG_DATA, challenge_msg)
    client_received = transfer(encrypted_challenge)
    _, challenge_data = client_transport.recv_record(client_received)
    recv_challenge, recv_ephem, recv_wrapped = AgeSh::Messages.read_auth_challenge(challenge_data)

    # === Client unwraps challenge ===
    decrypted = AgeSh::Crypto::AuthWrap.unwrap(recv_ephem, recv_wrapped, sec_bytes, pub_bytes)
    decrypted.should eq(recv_challenge)

    # === Client sends AUTH_RESPONSE -> Server reads it ===
    response = AgeSh::Messages.write_auth_response(decrypted)
    encrypted_response = client_transport.send_record(AgeSh::Constants::TAG_DATA, response)
    server_received = transfer(encrypted_response)
    _, response_data = server_transport.recv_record(server_received)
    recv_response = AgeSh::Messages.read_auth_response(response_data)
    recv_response.should eq(challenge)

    # === Server sends AUTH_RESULT -> Client reads it ===
    result = AgeSh::Messages.write_auth_result(true, "")
    encrypted_result = server_transport.send_record(AgeSh::Constants::TAG_DATA, result)
    client_received = transfer(encrypted_result)
    _, result_data = client_transport.recv_record(client_received)
    success, message = AgeSh::Messages.read_auth_result(result_data)
    success.should be_true
  end

  it "rejects when client uses wrong secret key" do
    keypair = Age.keygen
    wrong_keypair = Age.keygen
    _, pub_bytes = Age::Bech32.decode(keypair.public_key.value)
    _, wrong_sec_bytes = Age::Bech32.decode(wrong_keypair.secret_key.value.downcase)
    _, wrong_pub_bytes = Age::Bech32.decode(wrong_keypair.public_key.value)

    transport_key = Random::Secure.random_bytes(32)
    client_transport = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
    server_transport = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

    # Client sends AUTH_REQUEST -> Server reads it
    request = AgeSh::Messages.write_auth_request("testuser", keypair.public_key.value)
    encrypted_request = client_transport.send_record(AgeSh::Constants::TAG_DATA, request)
    server_received = transfer(encrypted_request)
    _, request_data = server_transport.recv_record(server_received)
    _username, pubkey_str = AgeSh::Messages.read_auth_request(request_data)

    # Server sends challenge -> Client reads it
    challenge = Random::Secure.random_bytes(AgeSh::Constants::CHALLENGE_SIZE)
    ephemeral_pub, wrapped = AgeSh::Crypto::AuthWrap.wrap(challenge, pub_bytes)
    challenge_msg = AgeSh::Messages.write_auth_challenge(challenge, ephemeral_pub, wrapped)
    encrypted_challenge = server_transport.send_record(AgeSh::Constants::TAG_DATA, challenge_msg)
    client_received = transfer(encrypted_challenge)
    _, challenge_data = client_transport.recv_record(client_received)
    _recv_challenge, recv_ephem, recv_wrapped = AgeSh::Messages.read_auth_challenge(challenge_data)

    # Client tries to unwrap with wrong key — should fail
    expect_raises(Age::Error) do
      AgeSh::Crypto::AuthWrap.unwrap(recv_ephem, recv_wrapped, wrong_sec_bytes, wrong_pub_bytes)
    end
  end
end
