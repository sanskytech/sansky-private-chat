"use client"; // Since this handles interactive elements, it's a client component

import React from "react";

interface GroupProps {
  name: string;
  lastMessage: string;
  onClick: () => void;
}

export default function GroupBand({ name, lastMessage, onClick }: GroupProps) {
  return (
    <div
      className="p-3 border-b border-gray-300 cursor-pointer hover:bg-gray-300 transition-all flex items-center gap-3"
      onClick={onClick}
    >
      {/* Circle with first letter */}
      <div className="w-10 h-10 flex items-center justify-center rounded-full bg-[#2F98BC] text-white text-lg font-bold">
        {name[0].toUpperCase()}
      </div>

      {/* User Details */}
      <div>
        <h3 className="font-bold">{name}</h3>
        <p className="text-sm text-gray-600">{lastMessage}</p>
      </div>
    </div>
  );
}
