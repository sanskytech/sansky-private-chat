'use client';

import { TextField } from "@mui/material";
import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";
import QRCodeStyling from "qr-code-styling";

const Page = () => {
    const qrRef = useRef(null); // `qrRef` is a reference to the <div> where the QR code will be rendered.
    const invitationCode = "ABC123"; // Example code - ideally fetched from backend

    useEffect(() => {
        if (!qrRef.current) return; // Prevents issues if `qrRef` is still null

        const qrCode = new QRCodeStyling({
            width: 200,
            height: 200,
            data: invitationCode, // This is the text inside the QR code
            dotsOptions: {
                color: "#2F98BC", // QR Code color
                type: "rounded"
            },
            backgroundOptions: {
                color: "#ffffff"
            },
            imageOptions: {
                crossOrigin: "anonymous",
                margin: 10
            }
        });

        qrCode.append(qrRef.current); // Append the QR code (this renders it)
        
    }, [invitationCode]);

    const handleCopyButton = () => {
        navigator.clipboard.writeText(invitationCode)
          .then(() => alert("Code copied to clipboard!"))
          .catch((error) => console.error('Failed to copy:', error));
    }
    
    
    return (
      <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
        {/* Logo positioned at top-left */}

        
  
        {/* Page Content */}
        <div className="flex flex-col  mt-4 p-10  rounded shadow-xl w-2/3 xl:w-4/11 bg-[#0795c64d] "  >
          
          <h2 className="text-center text-white mb-4">Invitation Code</h2>
          
                {/* QR Code Container */}
                <div ref={qrRef} className="flex justify-center mb-2" ></div>

            
                    

        

          
        <div className="flex justify-center items-center text-center w-full mt-5 mb-5 gap-2 ">
            <span  className="text-white" >Do not share the secret code with unknown person!</span>
            <Link href={'/create'} className="text-primary">Create Here</Link>
        </div>

        <div className="flex justify-start mb-2 gap-4 w-full">

          <button className="text-white font-bold py-2 px-4 rounded-xl cursor-pointer bg-[#2F98BC] flex-1" onClick={handleCopyButton} >
            Copy Code
          </button>

          <button className="text-white font-bold py-2 px-4 rounded-xl cursor-pointer bg-[#2F98BC] flex-1"
                onClick={() => {
                    const shareData = {
                        title: "Join SanskyChat",
                        text: `Hey! Join me on SanskyChat with this code: ${invitationCode}`,
                        url: `${window.location.origin}/join`,
                        };

                     if (navigator.share) {
                           navigator.share(shareData)
                              .then(() => console.log('Shared successfully'))
                             .catch((error) => console.error('Error sharing:', error));
                        } else {
                          alert("Sharing is not supported on this browser. Please copy the code manually.");
                      }
                  }}
                 >
                Share Code
          </button>


        </div>

        

        </div>

      </div>
    );
  }
  
  export default Page;
  

  