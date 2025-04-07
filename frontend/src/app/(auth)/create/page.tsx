"use client";
import { useState } from "react";
import Button from "@/components/Button";
import TextInputField from "@/components/CustomTextField";
import Link from "next/link";

const Page = () => {
  const [username, setUsername] = useState("");
  const [groupName, setGroupName] = useState("");
  const [encryptedToken, setEncryptedToken] = useState("");
  const [userId, setUserId] = useState("");

  const handleCreateRoom = async () => {
    try {
      const response = await fetch("http://localhost:5000/get-token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name: username, Group_Name: groupName }),
      });

      if (!response.ok) {
        throw new Error("Failed to create room");
      }

      const data = await response.json();
      setEncryptedToken(data.encrypted_data); // Store the encrypted token
      setUserId(data.user_id); // Store the user ID
      console.log("Encrypted Token:", data.encrypted_data);
      console.log("User ID:", data.user_id);
    } catch (error) {
      console.error("Error creating room:", error);
    }
  };

  return (
    <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
      <div className="w-11/12 md:w-6/12 xl:w-4/12 p-4 md:p-10 flex flex-col mt-4 rounded shadow-lg bg-[#0795c64d]">
        <h2 className="text-center text-white mb-4">Enjoy Security With Sanskytech</h2>

        {/* Username Input */}
        <TextInputField 
          label="Username" 
          required 
          value={username} 
          onChange={(e: any) => setUsername(e.target.value)} 
        />

        {/* Group Name Input */}
        <TextInputField 
          label="Groupname" 
          required 
          value={groupName} 
          onChange={(e: any) => setGroupName(e.target.value)} 
        />

        {/* Join Group Link */}
        <div className="flex justify-start gap-2 mb-2">
          <span className="text-xs sm:text-base text-white">Want to join a group?</span>
          <Link href={'/join'} className="text-xs sm:text-base text-primary">Join Here</Link>
        </div>

        {/* Create Room Button */}
        <Button label="Create Room" onClick={handleCreateRoom} />

        {/* Display the Encrypted Token and User ID */}
        {encryptedToken && (
          <div className="text-white mt-4">
            <p><strong>Encrypted Token:</strong> {encryptedToken}</p>
            <p><strong>User ID:</strong> {userId}</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Page;
