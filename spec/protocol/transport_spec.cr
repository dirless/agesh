require "../spec_helper"

describe AgeSh::Transport do
  describe "Direction" do
    it "encrypts and decrypts a single record" do
      key = Random::Secure.random_bytes(32)
      sender = AgeSh::Transport::Direction.new(key)
      receiver = AgeSh::Transport::Direction.new(key)
      plaintext = "hello world".to_slice

      ciphertext = sender.encrypt(plaintext)
      ciphertext.should_not eq(plaintext)
      ciphertext.size.should eq(plaintext.size + 16) # +16 for Poly1305 tag

      recovered = receiver.decrypt(ciphertext)
      recovered.should eq(plaintext)
    end

    it "encrypts multiple records with different ciphertexts" do
      key = Random::Secure.random_bytes(32)
      sender = AgeSh::Transport::Direction.new(key)
      plaintext = "same data".to_slice

      ct1 = sender.encrypt(plaintext)
      ct2 = sender.encrypt(plaintext)
      ct1.should_not eq(ct2) # different nonce counters

      # Decrypt both — order matters
      receiver = AgeSh::Transport::Direction.new(key)
      receiver.decrypt(ct1).should eq(plaintext)
      receiver.decrypt(ct2).should eq(plaintext)
    end

    it "fails on wrong counter order (replay detection)" do
      key = Random::Secure.random_bytes(32)
      sender = AgeSh::Transport::Direction.new(key)
      ct1 = sender.encrypt("first".to_slice)
      ct2 = sender.encrypt("second".to_slice)

      receiver = AgeSh::Transport::Direction.new(key)
      # Trying to decrypt ct2 first when it was the second record encrypted
      expect_raises(AgeSh::Error) do
        receiver.decrypt(ct2)
      end
    end

    it "round-trips empty payload" do
      key = Random::Secure.random_bytes(32)
      sender = AgeSh::Transport::Direction.new(key)
      receiver = AgeSh::Transport::Direction.new(key)
      ct = sender.encrypt(Bytes.new(0))
      receiver.decrypt(ct).should eq(Bytes.new(0))
    end
  end

  describe "Session" do
    it "round-trips tagged records bidirectionally" do
      transport_key = Random::Secure.random_bytes(32)
      client = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
      server = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

      # Client -> Server
      client_record = client.send_record(AgeSh::Constants::TAG_DATA, "hello server".to_slice)
      tag, payload = server.recv_record(client_record)
      tag.should eq(AgeSh::Constants::TAG_DATA)
      String.new(payload).should eq("hello server")

      # Server -> Client
      server_record = server.send_record(AgeSh::Constants::TAG_DATA, "hello client".to_slice)
      tag, payload = client.recv_record(server_record)
      tag.should eq(AgeSh::Constants::TAG_DATA)
      String.new(payload).should eq("hello client")
    end

    it "fails if records are swapped between directions" do
      transport_key = Random::Secure.random_bytes(32)
      client = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
      server = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

      # Client encrypts for server
      record = client.send_record(AgeSh::Constants::TAG_DATA, "test".to_slice)

      # Client tries to decrypt its own record — should fail because
      # client.recv has different key than server.recv
      expect_raises(AgeSh::Error) do
        client.recv_record(record)
      end
    end

    it "handles multiple records in sequence" do
      transport_key = Random::Secure.random_bytes(32)
      sender = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Client)
      receiver = AgeSh::Transport::Session.new(transport_key, AgeSh::Transport::Role::Server)

      100.times do |i|
        msg = "message #{i}".to_slice
        record = sender.send_record(AgeSh::Constants::TAG_DATA, msg)
        tag, payload = receiver.recv_record(record)
        tag.should eq(AgeSh::Constants::TAG_DATA)
        payload.should eq(msg)
      end
    end
  end
end
