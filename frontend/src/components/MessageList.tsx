import { MessageProps } from "@/types/types";
import Message from "./Messate";




const MessageList = () => {
    const messages:MessageProps[] = [
        {
            message: "nothing much",
            timestamp: new Date("2025-04-01T12:00:00Z"),
            username: "Paniz",
            userImage: "",
        },
        {
            message: "Hello",
            timestamp: new Date("2025-01-01T12:00:00Z"),
            username: "Mohammad",
            userImage: "",
            isCurrentUser: true
        },
        {
            message: "Hi",
            timestamp: new Date("2025-02-01T12:00:00Z"),
            username: "Paniz",
            userImage: "",
        },
        {
            message: "what's up?",
            timestamp: new Date("2025-03-01T12:00:00Z"),
            username: "Mohammad",
            userImage: "",
            isCurrentUser: true
        },
        {
            message: "I'm good, thank you",
            timestamp: new Date("2025-06-01T12:00:00Z"),
            username: "Paniz",
            userImage: "",
        },
        {
            message: "How are you?",
            timestamp: new Date("2025-05-01T12:00:00Z"),
            username: "Mohammad",
            userImage: "",
            isCurrentUser: true
        }
    ]


  messages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  return (
    <div className={`flex flex-col gap-2 p-2 w-full h-full overflow-y-auto`}>
        {messages.map((message, index) => (
            <Message key={index} {...message} />
        ))}
      
    </div>
  );
}


export default MessageList;