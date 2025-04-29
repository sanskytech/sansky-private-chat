'use client';

import Image from 'next/image';
import React, { useState } from "react";
import { useRouter } from "next/navigation";
import GroupBand from "@/components/GroupBand";
import KeyboardArrowLeftIcon from '@mui/icons-material/KeyboardArrowLeft';
import KeyboardArrowRightIcon from '@mui/icons-material/KeyboardArrowRight';
import Button from '@/components/Button';
import InviteDialog from "./InviteDialog";
import { InvitationCodeAction } from "@/actions/action"
//import { useActionState, useTransition, useEffect, useState, forwardRef } from "react";

//const initialState= {
 //   success: false,
 //   message: "",
 //   token: undefined
//};


type SidebarProps = {
    showCollapsedIcon:boolean;
    classNames?: string;

}

const Sidebar = ({showCollapsedIcon, classNames}:SidebarProps) =>{

    const router = useRouter();
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [isInvited, setIsInvited] = useState(false);
  
  
    const handleInviteClick = async(formData: FormData) => {
      // router.push("/invitation-code");
      setIsInvited(true);
      await InvitationCodeAction(formData);
    };

    const onInviteDialogClose = () => {
      setIsInvited(false);
    }
  
    const toggleSidebar = () => setIsCollapsed(!isCollapsed);

    

    return (
      <>
        <InviteDialog onInviteDialogClose={onInviteDialogClose} open={isInvited}/>
        <div
        className={`${isCollapsed ? ' w-full md:w-0' : '  '} ${classNames} transition-all duration-300 bg-gray-200 h-screen flex flex-col justify-between p-4 relative overflow-hidden`}
      >
        {/* Logo */}
        <Image 
          src="/Group-Name-min.png" 
          alt="Logo" 
          width={300}
          height={300}
          className={`absolute top-[-6px] left-5 p-4 z-0 ${isCollapsed ? 'hidden' : ''}`}
        />
        {
            showCollapsedIcon && 
            <Button label={isCollapsed ? <KeyboardArrowRightIcon  /> : <KeyboardArrowLeftIcon />}
                onClick={toggleSidebar}
                className={`absolute ${isCollapsed ? "rigt-[0px]" : "right-[-160px]" } top-1/2 transform -translate-y-1/2 p-1 bg-[#2F98BC] text-white rounded-full shadow-lg text-xs w-6 h-6 flex items-center justify-center`}
            />
        }

        <div className={`${isCollapsed ? 'block md:hidden' : 'block mt-32'}`}>
          {/* Group List */}
          <GroupBand 
            name="Paniz" 
            lastMessage="Hey! How are you?" 
            onClick={() => router.push("/chat/group-1")} 
          />
          <GroupBand 
            name="Mohammad" 
            lastMessage="Meeting at 3 PM" 
            onClick={() => router.push("/chat/group-2")} 
          />
        </div>

        {/* Bottom Buttons */}
        {!isCollapsed && (
          <div className={`flex flex-col gap-2 ${isCollapsed ? "" : " " } `}>
            <form action={handleInviteClick}>
              <Button
                type="submit" 
                label="Invite"
                className="text-white font-bold py-1.5 px-4 rounded-xl cursor-pointer bg-[#2F98BC]"
                //onClick={handleInviteClick}
              />
             </form>
            <Button 
              className="text-white font-bold py-1.5 px-4 rounded-xl cursor-pointer bg-[#2F98BC]"
              label="Logout"
            />
          </div>
        )}
      </div>

    </>
    )
}


export default Sidebar;