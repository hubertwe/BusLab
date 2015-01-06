#include <string>
#include <iostream>

class Message
{
public:

	enum Type
	{
		REGISTER_REQ,
		TEXT_MSG,
		BROADCAST_MSG,
		CLIENT_CONN_IND,
		CLIENT_QUIT_IND,
		SERVER_DIED
	};

	enum Status 
	{
		OK = 0,
		FAIL
	};

	Message(Type type, int source, int dest, const char* payload)
	{
		setType(type);
		setStatus(OK);
		setClientSource(source);
		setClientDestination(dest);
		setPayload(payload);
	}

	Message(Type type, int source, int dest, std::string payload)
	{
		setType(type);
		setStatus(OK);
		setClientSource(source);
		setClientDestination(dest);
		setPayload(payload.c_str());
	}

	Message()
	{ }

	friend std::ostream& operator<<(std::ostream& out, const Message& m) 
	{
		return out << std::endl <<
		"\tType: "<< m.getType() << std::endl <<
		"\tStatus: "<< m.getStatus() << std::endl <<
		"\tSource: "<< m.getClientSource() << std::endl <<
		"\tDestination: "<< m.getClientDestination() << std::endl <<
		"\tPAYLOAD: "<< std::string(m.getPayload());
	}

	static constexpr int getMessageSize()
	{
		return sizeof(Type) + sizeof(Status) + 2 * sizeof(int) + PAYLOAD_SIZE;
	}

	void serializeToBuffer(char* buffer)
	{
		buffer[0] = type_;
		buffer[1] = status_;
		buffer[2] = clientSource_;
		buffer[3] = clientDestination_;
		memcpy(buffer + sizeof(Type) + sizeof(Status) + 2 * sizeof(int), payload_, PAYLOAD_SIZE);
	}

	char* serialize()
	{
		serializeToBuffer(serialized_);
		return serialized_;
	}

	void deserializeFromBuffer(char* buffer)
	{
		type_ = static_cast<Type>(buffer[0]);
		status_ = static_cast<Status>(buffer[1]);
		clientSource_ = buffer[2];
		clientDestination_ = buffer[3];
		memcpy(payload_, buffer+ sizeof(Status) + sizeof(Type) + 2 * sizeof(int), PAYLOAD_SIZE);
	}

	void deserialize()
	{
		deserializeFromBuffer(serialized_);
	}

	void setType(Type type)
	{
		type_ = type;
	}

	void setStatus(Status status)
	{
		status_ = status;
	}

	void setClientDestination(int clientId)
	{
		clientDestination_ = clientId;
	}

	void setClientSource(int clientId)
	{
		clientSource_ = clientId;
	}

	void setPayload(const char* payload)
	{
		memcpy(payload_, payload, PAYLOAD_SIZE);
	}

	Type getType() const
	{
		return type_;
	}

	Status getStatus() const
	{
		return status_;
	}

	bool isStatusValid() const
	{
		return (getStatus() == OK);
	}

	int getClientSource() const
	{
		return clientSource_;
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
	Status status_;
	int clientDestination_;
	int clientSource_;
	char payload_[PAYLOAD_SIZE];
	char serialized_[PAYLOAD_SIZE + 2* sizeof(int) + sizeof(Type) + sizeof(Status)];
};

