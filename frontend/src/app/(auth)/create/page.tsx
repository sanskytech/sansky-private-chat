import { TextField } from "@mui/material";
import Link from "next/link";

const Page = () => {
    return (
      <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
        {/* Logo positioned at top-left */}

        
  
        {/* Page Content */}
        <div className="flex flex-col  mt-4 p-10 rounded shadow-lg w-2/3 xl:w-4/11 bg-[#0795c64d] "  >
          
          <h2 className="text-center text-white mb-4">Enjoy Security With Sanskytech</h2>
          <TextField
              required
              id="outlined-required"
              label="Username"
              margin="normal"
              className="rounded-xl my-10 bg-white border border-[#0795C6] focus:border-[#0795C6] hover:border-[#0795C6]"
          />
          <TextField
              required
              id="outlined-required"
              label="Group Name"
              margin="normal"
              className="rounded-xl bg-white border border-[#0795C6] focus:border-[#0795C6] hover:border-[#0795C6]"
          />
          <div className="flex justify-start gap-2 mb-2">
            <span className="text-white">Want to join a group?</span>
            <Link href={'/join'} className="text-primary">Join Here</Link>
          </div>

          <button className="text-white font-bold py-2 px-4 rounded-xl bg-[#2F98BC] cursor-pointer">
            Create Room
          </button>
          </div>
      </div>
    );
  }
  
  export default Page;
  

  