import { Link } from 'react-router-dom'
import Filter from '../../layouts/components/Filter'
import ProducsItem from './ProductsItem'

import { BiChevronRight } from "react-icons/bi";
import { BiChevronsRight } from "react-icons/bi";
import { BiChevronsLeft } from "react-icons/bi";
import { useState, useEffect } from 'react';
import axios from 'axios'
const Index = () => {

    const api = "http://localhost:8080/api/product/getAllProduct";
    const [data, setData] = useState([]);
    function getData() {
        axios
            .get(api)
            .then(result => setData(result.data))
            .catch(err => console.log('err:', err));
    }

    const [currentPage, setCurrentPage] = useState(1);
    const handlePage = (pageNext) => {
        setCurrentPage(pageNext);
        window.scrollTo(0, 0);
    }
    const quantity = 12;
    const maxPage = data.length / quantity
    const lastIndex = currentPage * quantity;
    const firstIndex = lastIndex - quantity;
    const currentData = data.slice(firstIndex, lastIndex);
    let numberOfPage = [];

    for (var i = 0; i < maxPage; i++) {
        numberOfPage.push(i + 1);
    }

    useEffect(() => {
        getData();
    }, [])

    return (
        <>
            <div class="w-full">
                <div class="m-auto text-center">
                    <h1 class="lg:text-[42px] text-2xl capitalize m-auto mt-[20px] item-center">Products</h1>
                </div>
                <div class="flex  m-auto mt-[20px] w-[140px] justify-between">
                    <p class="flex-none"> <Link to="/">Home</Link> </p>
                    <p class="flex-none mt-[5px]"> <BiChevronRight /> </p>
                    <p class="flex-none">Products</p>
                </div>
                <div id='img-product' class=" flex mt-[110px] w-11/12 m-auto justify-between " >
                    <Filter />
                    <div id='right' class="w-9/12 flex-none ">
                        <div class="grid grid-cols-4 gap-x-6 gap-y-90 ">
                            {currentData.map((item, index) => (

                                <ProducsItem item={item} />
                            )
                            )
                            }
                        </div>

                    </div>
                </div>
                {numberOfPage.length > 1
                    ? <div class="switchPage flex w-[225px] justify-between mt-[85px] m-auto mb-[115px]">
                        <button class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(currentPage - 1)} disabled={currentPage < 2 ? true : false}><BiChevronsLeft /></button>
                        {numberOfPage.map((numPage) => (
                            <>
                                {numPage !== currentPage ? <div class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(numPage)}>{numPage}</div> : <div class="flex flex-none w-[45px] h-[45px] justify-center items-center bg-gray-100 boder rounded-full cusor:default " onClick={() => handlePage(numPage)}>{numPage}</div>
                                }
                            </>
                        )
                        )}
                        <button class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(currentPage + 1)} disabled={currentPage >= maxPage ? true : false}><BiChevronsRight /></button>
                    </div>
                    : <div class="switchPage flex w-[225px] justify-between mt-[85px] m-auto mb-[115px]"></div>
                }
            </div>
        </>
    );

}
export default Index
