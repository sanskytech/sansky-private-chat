"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation"; // Correct hook for navigation in Server Components
import GroupBand from "@/components/GroupBand";
import { ChevronLeft, ChevronRight } from "lucide-react"; // Icons for toggle button

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const router = useRouter();
  const [isCollapsed, setIsCollapsed] = useState(false);

  const handleInviteClick = () => {
    router.push("/invitation-code");
  };

  const toggleSidebar = () => setIsCollapsed(!isCollapsed);

  return (
    <div className={`flex`}>
      {/* Left Navigation */}
      <div
        className={` ${isCollapsed ? 'w-0' : 'w-1/4'} transition-all duration-300 bg-gray-200 h-screen flex flex-col justify-between p-4 relative overflow-hidden`}
      >
        {/* Toggle Button */}
        <button
          className="absolute right-[-7px] top-1/2 transform -translate-y-1/2 p-1 bg-[#2F98BC] text-white rounded-full shadow-lg text-xs w-6 h-6 flex items-center justify-center"
          onClick={toggleSidebar}
        >
          {isCollapsed ? <ChevronRight size={16} /> : <ChevronRight size={16} className="rotate-180" />}
        </button>

        <div className={`${isCollapsed ? 'hidden' : 'block'}`}>
          <h2>Left Navigation</h2>
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
          <div className="flex flex-col gap-2">
            <button
              className="text-white font-bold py-1.5 px-4 rounded-xl cursor-pointer bg-[#2F98BC]"
              onClick={handleInviteClick}
            >
              Invite
            </button>
            <button className="text-white font-bold py-1.5 px-4 rounded-xl cursor-pointer bg-[#2F98BC]">
              Logout
            </button>
          </div>
        )}
      </div>

      {/* Body */}
      <div className={`flex-1 bg-gray-100 h-screen`}>{children}</div>
    </div>
  );
}