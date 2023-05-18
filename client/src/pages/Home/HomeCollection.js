import HomeCollectionItem from './HomeCollectionItem';

import { Pagination } from 'swiper';

import { Swiper, SwiperSlide } from 'swiper/react';

// Import Swiper styles
import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/pagination';
import 'swiper/css/scrollbar';

const HomeCollection = () => {

    const data = [
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/6_37a6a5fc-944e-4249-ac0f-747b11508859.jpg?v=1628328826&width=360",
            title: "Glasses",
            amountItem: "0"
        },
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/2_1945f7f5-26d9-45aa-a1a5-f2f2f628ae8d.jpg?v=1628328726&width=360",
            title: "Leather Bag",
            amountItem: "32"
        },
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/3_050039b7-f5fd-4b27-b4da-3d0b651b7faf.jpg?v=1628328727&width=360",
            title: "Shoes",
            amountItem: "8"
        },
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/7_9eb34d4f-ba2c-4935-b755-ff2a7054ec12.jpg?v=1628328826&width=360",
            title: "Tops",
            amountItem: "10"
        },
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/4_21ce2d70-d5f1-45dd-9226-e6f842ed9bd2.jpg?v=1628328727&width=360",
            title: "Blazers",
            amountItem: "5"
        },
        {
            urlImage: "https://cdn.shopify.com/s/files/1/0591/1350/4958/files/7_f415264b-8244-46fc-bd83-f55a5d62851a.jpg?v=1628328826&width=360",
            title: "Basic",
            amountItem: "11"
        },
    ]

    return (
        <div>
            <p className="text-3xl mb-10">Season Collection</p>
            <Swiper
                modules={[Pagination]}
                spaceBetween={30}
                breakpoints={{
                    370: {
                        slidesPerView: 1.2,
                    },
                    768: {
                        slidesPerView: 5,
                    },
                }}
            >
                {data.map((item, index) => (
                    <SwiperSlide key={index}>
                        <HomeCollectionItem urlImage={item.urlImage} title={item.title} amountItem={item.amountItem} />
                    </SwiperSlide>
                ))}
            </Swiper>
        </div>
    )
}

export default HomeCollection