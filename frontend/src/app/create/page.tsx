import { TextField } from "@mui/material";
import Link from "next/link";

const Page = () => {
    return (
      <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
        {/* Logo positioned at top-left */}

        
  
        {/* Page Content */}
        <div className="flex flex-col gap-8 mt-4 p-10 bg-white rounded shadow-lg w-2/3 xl:w-4/11 ">
          
          <h2 className="text-center">Enjoy Security With Sanskytech</h2>
          <TextField
              required
              id="outlined-required"
              label="Username"
              className="rounded-xl"
          />
          <TextField
              required
              id="outlined-required"
              label="Group Name"
              className="rounded-xl"
          />
          <div className="flex justify-start gap-2">
            <span>Want to join a group?</span>
            <Link href={'/join'} className="text-primary">Join Here</Link>
          </div>

          <button className="bg-primary text-white font-bold py-2 px-4 rounded-xl">
            Create Room
          </button>
          </div>
      </div>
    );
  }
  
  export default Page;
  

  