import HomeBestSellerItem from './HomeBestSellerItem'
import { useState, useEffect } from 'react'
import axios from '../../api'

const HomeBestSeller = () => {

    const [data, setData] = useState([])
    const [limitItem, setLimitItem] = useState(15)

    useEffect(() => {
        axios.get("product/getAllProduct")
            .then(res => setData(res.data))
            .catch(e => console.log(e))
    }, [])

    return (
        <div className="">
            <p className="text-3xl text-center mb-10">Best Seller</p>
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                {data.map((item, index) => {
                    if (index >= limitItem) return
                    return <HomeBestSellerItem key={item.id} data={item} />
                })}
            </div>
            {data.length > limitItem
                &&
                <div className="mt-12 flex justify-center">
                    <button onClick={() => setLimitItem(prev => prev + 15)} className="w-full lg:w-auto py-2 px-7 font-medium border border-black rounded hover:text-white hover:bg-black hover:scale-110 transition duration-300">
                        Load More
                    </button>
                </div>
            }
        </div>
    )
}

export default HomeBestSeller