import MessageList from "@/components/MessageList"


const ChatPage = () => {
    return (
        <div className="relative flex flex-col h-screen w-full">
            {/* top band */}
            <div className={`absolute top-0 left-0 bg-blue-400 w-full h-[100px] z-10 `}>
                <h1 className="text-4xl font-bold text-white text-center">ChatName</h1>
            </div>
            <MessageList/>          
        </div>
    )
}

export default ChatPage

