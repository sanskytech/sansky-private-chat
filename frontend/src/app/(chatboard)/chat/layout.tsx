"use client"; 

import React from "react";
import { useRouter } from "next/navigation";  // Updated for Next.js App Router
import GroupBand from "@/components/GroupBand";  // Import GroupBand component

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const router = useRouter();  // Correct hook for navigation in Server Components

  const handleInviteClick = () => {  
    router.push("/invitation-code");
  };

  return (
    <div className={`flex`}>
      {/* Left Navigation */}
      <div className={`w-1/4 bg-gray-200 h-screen flex flex-col justify-between p-4`}>
        <div>
          <h2>Left Navigation</h2>
          {/* Add chat groups, user list, etc., here */}
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
      </div>

      {/* Body */}
      <div className={`w-3/4 bg-gray-100 h-screen`}>{children}</div>
    </div>
  );
}
