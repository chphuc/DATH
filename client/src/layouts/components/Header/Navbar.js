import { useState, useEffect } from 'react'

import NavBarItem from "./NavBarItem"
import OutsideAlerter from '../../../components/OutsideAlerter'

import { FiMenu } from 'react-icons/fi'
import { AiOutlineArrowLeft } from 'react-icons/ai'
import { MdOutlineKeyboardArrowRight } from 'react-icons/md'
import {Link} from 'react-router-dom'

const Navbar = () => {

    const moreInfoShopNavItem =
        <div className="cursor-pointer">
            <img src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/mega-menu-banner.jpg?v=1628329052&width=533" />
            <p className="py-3 text-xl font-medium">The New - Season Shoes Edit</p>
            <p className="font-medium">Shop now</p>
        </div>
    const moreInfoProductsNavItem = <h1>moreInfoProductsNavItem</h1>

    const navBar = [
        {
            title: 'Home',
            fullWidth: true,
            children: [
                {
                    title: "Home1",
                    children: [
                        {
                            title: 'Main home',
                            description: 'hot'
                        },
                        {
                            title: 'Woman wears',
                            description: 'hot'
                        },
                        {
                            title: 'Local brand',
                            description: 'hot'
                        },
                        {
                            title: 'Vogue',
                            description: 'hot'
                        },
                        {
                            title: 'Elegant mood',
                        },
                        {
                            title: 'Trendy style',
                        },
                        {
                            title: 'Feminine',
                        },
                        {
                            title: 'Instyle',
                        },
                        {
                            title: 'Chic',
                        },
                        {
                            title: 'Glamour',
                        },
                    ]
                },
                {
                    title: "Home2",
                    children: [
                        {
                            title: 'Ready to wear',
                        },
                        {
                            title: 'Fast fashion',
                            description: 'hot'
                        },
                        {
                            title: 'Modern day',
                        },
                        {
                            title: 'Bra store',
                        },
                        {
                            title: 'Backpack',
                        },
                        {
                            title: 'Jewelry',
                            description: 'hot'
                        },
                        {
                            title: 'Active wear',
                        },
                        {
                            title: 'Sneaker',
                            description: 'hot'
                        },
                        {
                            title: 'Watch',
                        },
                        {
                            title: 'Bags',
                        },
                    ]
                },
                {
                    title: "Home3",
                    children: [
                        {
                            title: 'Hat',
                        },
                        {
                            title: 'Baby',
                        },
                        {
                            title: 'Glasses',
                        },
                        {
                            title: 'Houseware',
                        },
                        {
                            title: 'Book',
                        },
                        {
                            title: 'Socks',
                            description: 'hot'
                        },
                        {
                            title: 'Bedding',
                        },
                        {
                            title: 'Living',
                        },
                        {
                            title: 'Hand santizer',
                        },
                        {
                            title: 'Plantie',
                        },
                    ]
                },
                {
                    title: "Home4",
                    children: [
                        {
                            title: 'Coffee',
                        },
                        {
                            title: 'Paintme',
                        },
                        {
                            title: 'Stationery',
                        },
                        {
                            title: 'Case phone',
                        },
                        {
                            title: 'Electronic',
                        },
                        {
                            title: 'Juice',
                        },
                        {
                            title: 'Mirror',
                        },
                        {
                            title: 'Supplyment',
                        },
                        {
                            title: 'Barber',
                        },
                        {
                            title: 'Furniture',
                        },
                    ]
                },
                {
                    title: "Home5",
                    children: [
                        {
                            title: 'Skateboard',
                        },
                        {
                            title: 'Pizza',
                        },
                        {
                            title: 'Print',
                        },
                        {
                            title: 'Nails polish',
                        },
                        {
                            title: 'Bathroom',
                        },
                        {
                            title: 'Skincare',
                            description: 'hot'
                        },
                        {
                            title: 'Toy',
                        },
                        {
                            title: 'Beauty',
                        },
                        {
                            title: 'Drink',
                        },
                        {
                            title: 'Candles',
                        },
                    ]
                },
                {
                    title: "Home6",
                    children: [
                        {
                            title: 'Pet',
                        },
                        {
                            title: 'Organic',
                        },
                        {
                            title: 'Postcard',
                        },
                        {
                            title: 'Speaker',
                        },
                        {
                            title: 'BFCM',
                        },
                        {
                            title: 'Christmas',
                        },
                        {
                            title: 'Gym',
                        },
                        {
                            title: 'POD store',
                            description: 'hot'
                        },
                    ]
                },
                {
                    title: "Home7",
                    children: [
                        {
                            title: 'Suftboard',
                            description: 'new'
                        },
                        {
                            title: 'Bike',
                            description: 'new'
                        },
                        {
                            title: 'Ceramic',
                            description: 'new'
                        },
                        {
                            title: 'Camping',
                            description: 'new'
                        },
                        {
                            title: 'Cake',
                            description: 'new'
                        },
                        {
                            title: 'Soap',
                            description: 'new'
                        },
                        {
                            title: 'Floral',
                            description: 'new'
                        },
                        {
                            title: 'Smart Light',
                            description: 'new'
                        },
                        {
                            title: 'Pet Clothes',
                            description: 'new'
                        },
                        {
                            title: 'Keyboard',
                            description: 'new'
                        },
                    ]
                },
            ]
        },
        {
            title: 'Shop',
            moreInfomation: moreInfoShopNavItem,
            fullWidth: true,
            children: [
                {
                    title: "Shop1",
                    children: [
                        {
                            title: 'Filter left sidebar'
                        },
                        {
                            title: 'Filter right sidebar'
                        },
                        {
                            title: 'Canvas sidebar'
                        },
                        {
                            title: 'Grid 2 columns'
                        },
                        {
                            title: 'Grid 3 columns'
                        },
                    ]
                },
                {
                    title: "Shop2",
                    children: [
                        {
                            title: 'Grid 4 columns'
                        },
                        {
                            title: 'Grid 5 columns'
                        },
                        {
                            title: 'List view'
                        },
                        {
                            title: 'Collection list'
                        },
                        {
                            title: 'Filter OS 2.0'
                        },
                    ]
                },
                {
                    title: "Shop3",
                    children: [
                        {
                            title: 'Pagination page'
                        },
                        {
                            title: 'Infinite scrolling'
                        },
                        {
                            title: 'Load more button'
                        },
                        {
                            title: 'Hidden sidebar'
                        },
                        {
                            title: 'Full-width layout'
                        },
                    ]
                },
                {
                    title: "Shop4",
                    children: [
                        {
                            title: 'Custom content'
                        },
                        {
                            title: 'Custom header banner'
                        },
                        {
                            title: 'Cookies law info'
                        },
                        {
                            title: 'Advance filters'
                        },
                    ]
                },
            ]
        },
        {
            title: <Link to="/product">Products</Link> ,
            moreInfomation: moreInfoProductsNavItem,
            fullWidth: true,
            children: [
                {
                    title: "Product1",
                    children: [
                        {
                            title: 'Grid 1 column'
                        },
                        {
                            title: 'Grid 2 columns'
                        },
                        {
                            title: 'Grid mix'
                        },
                        {
                            title: 'Grid 1 columns'
                        },
                        {
                            title: 'Grid 2 columnss'
                        },
                        {
                            title: 'Slide vertical'
                        },
                        {
                            title: 'Slide full-width'
                        },
                        {
                            title: 'Sticky add to cart'
                        },
                        {
                            title: 'Product with swatch'
                        },
                        {
                            title: 'Pre-order product'
                        },
                    ]
                },
                {
                    title: "Product2",
                    children: [
                        {
                            title: 'Product image swatch'
                        },
                        {
                            title: 'Product dropdown swatch'
                        },
                        {
                            title: 'Lightbox image'
                        },
                        {
                            title: 'Product video'
                        },
                        {
                            title: 'Product 3D, AR models'
                        },
                        {
                            title: 'Buy more save more'
                        },
                        {
                            title: 'Product bundles layout1'
                        },
                        {
                            title: 'Product bundles layout2'
                        },
                        {
                            title: 'Custom content'
                        },
                        {
                            title: 'Back in stock'
                        },
                    ]
                },
                {
                    title: "Product3",
                    children: [
                        {
                            title: 'Short description'
                        },
                        {
                            title: 'Real-time visitors'
                        },
                        {
                            title: 'Stock countdown'
                        },
                        {
                            title: 'Sale notification'
                        },
                        {
                            title: 'Product countdown timer'
                        },
                        {
                            title: 'Custom field'
                        },
                        {
                            title: 'Dynamic checkout button'
                        },
                        {
                            title: 'Trust badge'
                        },
                        {
                            title: 'Delivery infomation'
                        },
                        {
                            title: 'Variant group images'
                        },
                    ]
                },
                {
                    title: "Product4",
                    children: [
                        {
                            title: 'Collapsible tabs infomation'
                        },
                        {
                            title: 'Product tabs infomation'
                        },
                        {
                            title: 'Products recently viewed'
                        },
                        {
                            title: 'Product recommendations'
                        },
                        {
                            title: 'Single product layout1'
                        },
                        {
                            title: 'Single product layout2'
                        },
                        {
                            title: 'Single product layout3'
                        },
                        {
                            title: 'Single product layout4'
                        },
                        {
                            title: 'Single product layout5'
                        },
                        {
                            title: 'Single product layout6'
                        },
                    ]
                },
            ]
        },
        {
            title: 'Pages',
            fullWidth: false,
            children: [
                {
                    title: 'About us'
                },
                {
                    title: 'Contact1'
                },
                {
                    title: 'Contact2'
                },
                {
                    title: 'FAQs'
                },
                {
                    title: 'Find a store'
                },
                {
                    title: 'My account'
                },
            ]
        },
        {
            title: 'Blogs',
            fullWidth: false,
            children: [
                {
                    title: 'Grid layout'
                },
                {
                    title: 'List view'
                },
                {
                    title: 'Blog with left sidebar'
                },
                {
                    title: 'Blog with rigth sidebar'
                },
                {
                    title: 'Single post style 1'
                },
                {
                    title: 'Single post style 2'
                },
            ]
        },
        {
            title: 'Features',
            fullWidth: true,
            children: [
                {
                    title: "Feature1",
                    children: [
                        {
                            title: 'Header 1'
                        },
                        {
                            title: 'Header 2'
                        },
                        {
                            title: 'Header 3'
                        },
                        {
                            title: 'Header 4'
                        },
                        {
                            title: 'Header 5'
                        },
                        {
                            title: 'Header 6'
                        },
                    ]
                },
                {
                    title: "Feature2",
                    children: [
                        {
                            title: 'Annoucement bar 1'
                        },
                        {
                            title: 'Annoucement bar 2'
                        },
                        {
                            title: 'Slideshow'
                        },
                        {
                            title: 'Featured promotion'
                        },
                        {
                            title: 'Featured collection'
                        },
                        {
                            title: 'Image with text'
                        },
                    ]
                },
                {
                    title: "Feature3",
                    children: [
                        {
                            title: 'Newsletter'
                        },
                        {
                            title: 'Custom content'
                        },
                        {
                            title: 'Testimonial 1'
                        },
                        {
                            title: 'Testimonial 2'
                        },
                        {
                            title: 'Testimonial 3'
                        },
                        {
                            title: 'Testimonial 4'
                        },
                    ]
                },
                {
                    title: "Feature4",
                    children: [
                        {
                            title: 'Video'
                        },
                        {
                            title: 'Countdown timer'
                        },
                        {
                            title: 'Press'
                        },
                        {
                            title: 'Image cards'
                        },
                        {
                            title: 'Lookbook'
                        },
                        {
                            title: 'Featured products slider'
                        },
                    ]
                },
                {
                    title: "Feature5",
                    children: [
                        {
                            title: 'Collection list 1'
                        },
                        {
                            title: 'Collection list 2'
                        },
                        {
                            title: 'Collection list 3'
                        },
                        {
                            title: 'Collection list 4'
                        },
                        {
                            title: 'Collection list 5'
                        },
                        {
                            title: 'Image with text overlay'
                        },
                    ]
                },
                {
                    title: "Feature6",
                    children: [
                        {
                            title: 'Product tabs 1'
                        },
                        {
                            title: 'Product tabs 2'
                        },
                        {
                            title: 'Instagram'
                        },
                        {
                            title: 'Blog posts'
                        },
                        {
                            title: 'Brands list'
                        },
                        {
                            title: 'Footer'
                        },
                    ]
                },
                {
                    title: "Feature7",
                    children: [
                        {
                            title: 'RTL Layout'
                        }
                    ]
                }
            ]
        },
    ]

    const [showNav, setShowNav] = useState(false)
    const [history, setHistory] = useState([navBar])
    const current = history[history.length - 1]
    const [navbarStyle, setNavbarStyle] = useState("-translate-x-full")

    // -----------------------

    const onOpenNavbar = () => {
        setShowNav(true)
        setTimeout(() => {
            setNavbarStyle("translate-x-0")
        }, 50);
    }

    const onClickNavbar = (index) => {
        if (!current[index].children) return
        setHistory(prev => [...prev, current[index].children])
    }

    const onClostNavbar = () => {
        setHistory([navBar])
        setNavbarStyle("-translate-x-full")
        setTimeout(() => {
            setShowNav(false)
        }, 300);
    }

    const onBackNavbar = () => {
        setHistory((prev) => (prev.slice(0, -1)))
    }
    return (
        <>
            {showNav &&
                <div className="fixed top-0 right-0 w-full h-full bg-black bg-opacity-30 z-10 lg:hidden">
                    <OutsideAlerter todo={onClostNavbar} compStyle={"absolute top-0 left-0 w-10/12 h-full bg-white px-4 transition duration-300 " + (history.length <= 1 ? "py-4 " : " ") + navbarStyle}>
                        {history.length > 1 &&
                            <div
                                className="flex items-center font-medium py-4 cursor-pointer"
                                onClick={onBackNavbar}
                            >
                                <div>
                                    <AiOutlineArrowLeft />
                                </div>
                                <p className="ml-3">Back</p>
                            </div>
                        }
                        <div className={" " + (history.length <= 1 ? "pt-8" : "")}>
                            {current.map((item, index) => (
                                <div key={index} onClick={() => onClickNavbar(index)} className="flex items-center justify-between py-3 cursor-pointer">
                                    <p>{item.title}</p>
                                    {item.children &&
                                        <div className="text-xl">
                                            <MdOutlineKeyboardArrowRight />
                                        </div>
                                    }
                                </div>
                            ))}
                        </div>
                        {history.length <= 1 &&
                            <div className="mt-16">
                                <p className="text-xl font-medium mb-6">My Account</p>
                                <div>
                                    <button className="w-full bg-black font-medium text-white py-3 px-4 rounded-lg mb-4">
                                        Log in
                                    </button>
                                    <button className="w-full text-black border font-medium border-black py-3 px-4 rounded-lg">
                                        Register
                                    </button>
                                </div>
                            </div>
                        }
                    </OutsideAlerter>
                </div>
            }

            <div className="hidden lg:flex items-center relative">
                {navBar.map((item, index) => (
                    <div key={item.title} className={index != 0 ? 'ml-5' : ''}>
                        <NavBarItem title={item.title} fullWidth={item.fullWidth} moreInfomation={item.moreInfomation} children={item.children} />
                    </div>
                ))}
            </div>
            <div
                className="flex-1 lg:hidden text-2xl cursor-pointer"
                onClick={onOpenNavbar}
            >
                <FiMenu />
            </div>
        </>
    )
}

export default Navbar