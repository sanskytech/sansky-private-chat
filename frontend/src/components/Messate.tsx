import { MessageProps } from "@/types/types";



const Message = ({ message }:MessageProps) => {
    return (
        <div className="message">
            {message}
        </div>
    );
};

export default Message;