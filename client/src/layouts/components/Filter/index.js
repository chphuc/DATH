const Filter = () => {
    return (
        <div id='left' class="w-1/5 flex-none  text-left">
            <h3 class="text-3xl mb-[50px] font-medium">Filters</h3>

            <div class="w-95/100  ">
                <h4 class=" mb-4 !text-lg font-medium">Size</h4>
                <div class="flex justify-between">
                    <div class="flex w-17/100 aspect-square justify-center items-center rounded-md border-gray-300 border border-solid flex-none hover:bg-black hover:text-white hover:cursor-pointer transition ease-in-out"><a href="">XS</a></div>
                    <div class="flex w-17/100 aspect-square justify-center items-center rounded-md border-gray-300 border border-solid flex-none hover:bg-black hover:text-white hover:cursor-pointer transition ease-in-out"><a href="">S</a></div>
                    <div class="flex w-17/100 aspect-square justify-center items-center rounded-md border-gray-300 border border-solid flex-none hover:bg-black hover:text-white hover:cursor-pointer transition ease-in-out"><a href="">ML</a></div>
                    <div class="flex w-17/100 aspect-square justify-center items-center rounded-md border-gray-300 border border-solid flex-none hover:bg-black hover:text-white hover:cursor-pointer transition ease-in-out"><a href="">L</a></div>
                    <div class="flex w-17/100 aspect-square justify-center items-center rounded-md border-gray-300 border border-solid flex-none hover:bg-black hover:text-white hover:cursor-pointer transition ease-in-out"><a href="">XL</a></div>
                </div>
            </div>

            <div class="w-95/100  mt-[45px]">
                <h4 class=" mb-4 !text-lg font-medium">Prices</h4>
                <div class="text-gray-400">
                    <p class="mb-[10px] hover:cursor-pointer hover:text-black "><a class="underline-hover-effect" href="">$0-$50</a></p>
                    <p class="mb-[10px] hover:cursor-pointer  hover:text-black"><a class="underline-hover-effect" href="">$50-$100</a></p>
                    <p class="mb-[10px] hover:cursor-pointer   hover:text-black"><a class="underline-hover-effect" href="">$100-$150</a></p>
                    <p class="mb-[10px] hover:cursor-pointer  hover:text-black"><a class="underline-hover-effect" href="">$150-$200</a></p>

                    <p class="mb-[10px] hover:cursor-pointe hover:text-black"><a class="underline-hover-effect" href="">$300-$400</a></p>

                </div>
            </div>

            <div class="w-95/100  mt-[45px]">
                <h4 class=" mb-4 !text-lg font-medium">Brands</h4>
                <div class="text-gray-400 flex justify-between ">
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Minimog</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Retrolie</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Abby</a></p>
                </div>
                <div class="text-gray-400 flex justify-between w-[140px]">
                    <p class="hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Learts</a></p>
                    <p class="hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Vagabond</a></p>
                </div>
            </div>

            <div class="w-95/100  mt-[45px]">
                <h4 class=" mb-4 !text-lg font-medium">Tags</h4>
                <div class="text-gray-400 flex justify-between">
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Dress</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Hats</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Sandal</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Belt</a></p>
                </div>
                <div class="text-gray-400 flex justify-between w-49/50">
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Bags</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Snacker</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Denim</a></p>
                </div>
                <div class="text-gray-400 flex justify-between w-49/50">
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Vagabond</a></p>
                    <p class="mb-[10px] hover:underline hover:cursor-pointer transition ease-in-out hover:text-black"><a href="">Sunglasses</a></p>
                </div>
                <div class="text-gray-400 flex justify-between w-49/50">
                    <p class="hover:underline hover:cursor-pointer transition ease-in-out hover:text-black "><a href="">Vintage</a></p>
                </div>
            </div>
        </div>
    );
}

export default Filter