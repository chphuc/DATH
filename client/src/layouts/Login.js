import { Pagination, A11y } from 'swiper';

import { Swiper, SwiperSlide } from 'swiper/react';

// Import Swiper styles
import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/pagination';
import 'swiper/css/scrollbar';

const Login = ({ children }) => {
    return (
        <div className="flex">
            <div className="lg:w-1/3">
                {children}
            </div>
            <div className="lg:w-2/3">
                <Swiper
                    modules={[Pagination, A11y]}
                    spaceBetween={0}
                    slidesPerView={1}
                    pagination={{ clickable: true }}
                    className="w-full h-full"
                >
                    <SwiperSlide>
                        <div
                            style={{
                                backgroundImage: `url("https://img.freepik.com/free-psd/online-shopping-with-laptop-mockup-template-shopping-elements_1150-38886.jpg?w=900&t=st=1665066844~exp=1665067444~hmac=1c6b043ccb7a8d37a420eb9a8e837af1f572db6fd5a4172a31815cbe34fe3ea3")`,
                                backgroundPosition: 'center',
                                backgroundSize: 'cover'
                            }}
                            className="w-full h-full"
                        >
                        </div>
                    </SwiperSlide>
                    <SwiperSlide>
                        <div
                            style={{
                                backgroundImage: `url("https://img.freepik.com/free-vector/customer-receiving-package-from-courier-hands-deliveryman-hands-giving-parcel-box-gift-order-clients-hands-flat-vector-illustration-delivery-shipping-transportation-concept_74855-24420.jpg?w=996&t=st=1665075657~exp=1665076257~hmac=a1eab209c4d85d5e130732ab5acebfb750f54726f2d0e4a0a617a54a0505df5f")`,
                                backgroundPosition: 'center',
                                backgroundSize: 'cover'
                            }}
                            className="w-full h-full"
                        >
                        </div>
                    </SwiperSlide>
                    <SwiperSlide>
                        <div
                            style={{
                                backgroundImage: `url("https://img.freepik.com/free-photo/beautiful-smart-asian-young-entrepreneur-business-woman-owner-sme-online-checking-product_7861-1183.jpg?w=1060&t=st=1665075331~exp=1665075931~hmac=37d21e66d30537c5726738bf36cb43870475c72128f8120b48d2af222bc502f9")`,
                                backgroundPosition: 'center',
                                backgroundSize: 'cover'
                            }}
                            className="w-full h-full"
                        >
                        </div>
                    </SwiperSlide>
                </Swiper>
            </div>
        </div>
    )
}

export default Login