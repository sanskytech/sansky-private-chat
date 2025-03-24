'use client';

import { MessageProps } from "@/types/types";
import Avatar from '@mui/material/Avatar';


const Message = ({ message, userImage, username, timestamp, isCurrentUser }:MessageProps) => {

    console.log(username + " " + isCurrentUser);

    return (
        <div className={`flex  flex-col w-full my-2   p-2`}>
            <div className={` flex flex-col  ${isCurrentUser ? "items-end pl-10 md:pl-60  " : "items-start pr-10 md:pr-60"}`}>

                <Avatar alt={username} src={userImage? userImage : ""}
                    className={`!w-6 !h-6 !text-xs !my-2    ${isCurrentUser? "!bg-primary/40" : "!bg-secondary/40"}`}                
                >
                    {username.charAt(0).toUpperCase()}
                </Avatar>
                <div className={`message flex flex-row rounded-xl  ${isCurrentUser? "flex-row-reverse bg-primary/40" : "bg-secondary/40"} gap-2 p-2 items-start`}>
                    <span className={`text-bold text-xs p-2 rounded-xl    ${isCurrentUser ? "bg-primary/40" : "bg-secondary/40"} `} >{username}</span>
                    <div className="message-content text-lg px-2">
                        {message}
                    </div>
                </div>
                    <span className="message-timestamp text-xs text-gray-500 mt-1 ">
                        {new Date(timestamp).toLocaleString()}
                    </span>
            </div>
        </div>
    );
};

export default Message;