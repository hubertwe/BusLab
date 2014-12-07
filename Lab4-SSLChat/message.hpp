#include <string>
#include <iostream>

#define stringify
class Message
{
public:

	enum Type
	{
		REGISTER_REQ,
		REGISTER_RESP,
		TEXT_MSG,
		TEXT_MSG_RESP,
		BROADCAST_MSG,
		BROADCAST_MSG_RESP
	};

	Message(Type type, int dest, const char* payload)
	{
		setType(type);
		setClientDestination(dest);
		setPayload(payload);
	}

	Message()
	{
	}

	friend std::ostream& operator<<(std::ostream& out, const Message& m) 
	{
		return out << std::endl <<
		"\tType: "<< m.getType() << std::endl <<
		"\tDestination: "<< m.getClientDestination() << std::endl <<
		"\tPAYLOAD: "<< std::string(m.getPayload());
	}

	static constexpr int getMessageSize()
	{
		return sizeof(Type) + sizeof(int) + PAYLOAD_SIZE;
	}

	void serializeToBuffer(char* buffer)
	{
		buffer[0] = type_;
		buffer[1] = clientDestination_;
		memcpy(buffer+sizeof(Type)+sizeof(int), payload_, PAYLOAD_SIZE);
	}

	char* serialize()
	{
		serializeToBuffer(serialized_);
		return serialized_;
	}


	void deserializeFromBuffer(char* buffer)
	{
		type_ = static_cast<Type>(buffer[0]);
		clientDestination_ = buffer[1];
		memcpy(payload_, buffer+sizeof(Type)+sizeof(int), PAYLOAD_SIZE);
	}

	void deserialize()
	{
		deserializeFromBuffer(serialized_);
	}

	void setType(Type type)
	{
		type_ = type;
	}

	void setClientDestination(int clientId)
	{
		clientDestination_ = clientId;
	}

	void setPayload(const char* payload)
	{
		memcpy(payload_, payload, PAYLOAD_SIZE);
	}

	Type getType() const
	{
		return type_;
	}

	int getClientDestination() const
	{
		return clientDestination_;
	}

	char* getPayload() const
	{
		return const_cast<char*>(payload_);
	}

	char* getBuffer()
	{
		return serialized_;
	}

private:
	const static int PAYLOAD_SIZE = 1024;

	Type type_;
	int clientDestination_;
	char payload_[PAYLOAD_SIZE];
	char serialized_[PAYLOAD_SIZE+sizeof(int)+sizeof(Type)];
};

