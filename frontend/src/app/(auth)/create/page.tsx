import Button from "@/components/Button";
import TextInputField from "@/components/CustomTextField";
import Link from "next/link";

const Page = () => {
    return (
      <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
        {/* Logo positioned at top-left */}

        
  
        {/* Page Content */}
        <div className="w-11/12 md:w-6/12 xl:w-4/12 p-4 md:p-10 flex flex-col  mt-4  rounded shadow-lg  bg-[#0795c64d] "  >
          
          <h2 className="text-center text-white mb-4">Enjoy Security With Sanskytech</h2>
          <TextInputField label={"Username"} required />       
          <TextInputField label={"Email"} required />
          <div className="flex justify-start gap-2 mb-2">
            <span className="text-xs sm:text-base text-white">Want to join a group?</span>
            <Link href={'/join'} className="text-xs sm:text-base text-primary">Join Here</Link>
          </div>
          <Button label="Create Room" />
          </div>
      </div>
    );
  }
  
  export default Page;
  

  