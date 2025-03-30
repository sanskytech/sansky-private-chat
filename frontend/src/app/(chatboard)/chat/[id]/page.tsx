'use client';

import InputField from "@/components/InputField"
import MessageList from "@/components/MessageList"
import React, { useState } from "react";
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import Sidebar from "@/components/Sidebar";
import { useRouter } from "next/navigation";


const ChatPage = () => {
    // const [isSidebarOpened,SetSidebarOpen] = useState(false);
    const router = useRouter();

    return (
        <div className={`flex flex-row  h-screen w-full `}>
            <div className={`hidden md:block `}>
                <Sidebar showCollapsedIcon={true} classNames={`w-full`} />
            </div>
            
            <div className={`relative flex-col flex w-content`}>
                <div className={`absolute left-4 top-4 z-100 cursor-pointer text-white block md:hidden `} onClick={() => router.push("/chat")}>
                    <ArrowBackIcon fontSize={`large`} />
                </div>
                {/* top band */}
                <div className={`absolute top-0 left-0 bg-[#4BA6CB]  w-full h-[75px] z-10 `}>
                    <h1 className="text-4xl font-bold text-white text-center">ChatName</h1>
                </div>
                {/* body */}
                <div className="flex-1 overflow-y-scroll bg-gray-100 pt-[100px] mb-[60px]">
                    {/* MessageList */}
                    <MessageList/> 
                </div>

                {/* bottom band */}
                <div className="absolute bottom-4 left-0 px-4 w-full h-[50px] z-10">
                <InputField />
                </div>        
            </div>

        </div>
    )
}

export default ChatPage

