import banner1 from '../../assets/banner1.jpg'

import { Pagination, A11y } from 'swiper';

import { Swiper, SwiperSlide } from 'swiper/react';

// Import Swiper styles
import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/pagination';
import 'swiper/css/scrollbar';

const HomeBanner = () => {
    return (
        <Swiper
            modules={[Pagination, A11y]}
            spaceBetween={0}
            slidesPerView={1}
            pagination={{ clickable: true }}
        >
            <SwiperSlide>
                <div
                    style={{
                        height: '570px',
                        backgroundImage: `url(${banner1})`,
                        backgroundPosition: 'center',
                        backgroundSize: 'cover'
                    }}
                    className="w-full"
                >
                </div>
            </SwiperSlide>
            <SwiperSlide>
                <div
                    style={{
                        height: '570px',
                        backgroundImage: `url("https://img.ltwebstatic.com/images3_ach/2022/09/09/16626907321167ba0f84252e89c38dc5aa3c47e311.gif")`,
                        backgroundPosition: 'center',
                        backgroundSize: 'cover'
                    }}
                    className="w-full"
                >
                </div>
            </SwiperSlide>
        </Swiper>
    )
}

export default HomeBanner