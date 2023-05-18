import { BiChevronRight } from "react-icons/bi";
import { BiStar } from "react-icons/bi";
import { BiGitCompare } from "react-icons/bi";
import { BsQuestionCircle } from "react-icons/bs";
import { BsShare } from "react-icons/bs";
import { Link, useLocation, useNavigate } from 'react-router-dom';
import React from 'react'
import { useState, useEffect } from "react";

import { useSelector, useDispatch } from 'react-redux'
import { add } from '../../features/cart/cartSlice'

import { toast } from 'react-toastify';

const Index = (props) => {
	const navigate = useNavigate()
	const dispatch = useDispatch()

	const location = useLocation();
	const state = location.state;


	var desRef = React.useRef();
	var reRef = React.useRef();
	var polRef = React.useRef();
	var bt1 = React.useRef();
	var bt2 = React.useRef();
	var bt3 = React.useRef();

	const display_Tab = (buRef, coRef) => {
		bt1.current.style.color = "rgb(204, 204, 204)";
		bt2.current.style.color = "rgb(204, 204, 204)";
		bt3.current.style.color = "rgb(204, 204, 204)";
		desRef.current.style.display = "none";
		reRef.current.style.display = "none";
		polRef.current.style.display = "none";
		var BURef = buRef;
		var CoRef = coRef;
		BURef.current.style.color = "black";
		CoRef.current.style.display = "block";

	}

	const [count, updateCount] = useState(1);

	const addCount = () => {
		updateCount(count + 1);
	}

	const minusCount = () => {
		if (count <= 1) {
			updateCount(1)
		}
		else {
			updateCount(count - 1);
		}
	}

	const notifySuccessAddItem = () => toast.success('Add success!', {
		position: "top-right",
		autoClose: 1000,
		hideProgressBar: false,
		closeOnClick: true,
		pauseOnHover: true,
		draggable: true,
		progress: undefined,
		theme: "light",
	});

	const handleAddCart = () => {
		dispatch(add({
			data: state,
			amount: count
		}))
		notifySuccessAddItem()
	}
	const handleBuyNow = () => {
		dispatch(add({
			data: state,
			amount: count
		}))
		navigate('/checkout')
	}

	useEffect(() => {
		window.scrollTo(0, 0)
	}, [])

	return (
		<div  >
			<div class="flex w-[340px] m-auto mt-[30px] justify-between">
				<p class="flex-none"> <Link to="/">Home</Link> </p>
				<p class="flex-none  mt-[5px]"> <BiChevronRight /> </p>
				<p class="flex-none"><Link to="/product">Products</Link></p>
				<p class="flex-none  mt-[5px] "> <BiChevronRight /> </p>
				<p class="flex-none ">{state.name}</p>
			</div>
			<div>
				<div>
					<div classname="Item_detail" class="w-73/100 h-[660px] xl: flex justify-between mt-[40px] m-auto  mb-[150px] ">
						<div id="Item" class="w-44/100 flex-none overflow-hidden">
							<img class=" overflow-hidden hover:scale-110 duration-150 aspect-24/29" src={state.image[0]} alt="image here" />
						</div>
						<div id="Info" class="w-52/100 text-left flex-none">
							<div class="text-color-subtext uppercase text-sm text-gray-500">
								MINIMOG
							</div>
							<h1 class="text-2xl md:text-3xl md:leading-[42px] pr-2 mt-[15px]">{state.name}</h1>
							<p class="flex mt-[5px]"><BiStar /> <BiStar /> <BiStar /> <BiStar /> <BiStar /></p>
							<p class="f-price-item f-price-item--regular text-xl md:text-2xl mt-[17px]">$ {state.price.toFixed(2)}</p>
							<div class="text-gray-500 mt-[20px]">Only <strong>{state.remained}</strong> item(s) left in stock!</div>
							<div class="h-[5px] bg-gray-200 flex rounded-md mt-[10px]">
								<div class="w-5/100 bg-red-500 flex-none rounded-md"></div>
							</div>
							<p class="font-medium hidden md:block mt-[25px]">Quantity </p>

							<div class="h-[50px] flex justify-between mt-[10px]">
								<div class=" w-23/100 h-[50px] rounded-md border-gray-300 border border-solid flex flex-none justify-around items-center">
									<button type="button" id="button_left" class="flex-none text-2xl " onClick={minusCount}>-</button>
									<p class="flex-none">{count}</p>
									<button type="button" id="button_right" class="flex-none text-2xl" onClick={addCount}>+</button>
								</div>
								<button onClick={handleAddCart} type="button" id="button_right" class="w-73/100 h-[50px] rounded-md border-black border border-solid flex-none transition ease-in-out duration-300 hover:bg-black hover:text-white hover:scale-105 ">Add to cart</button>
							</div>
							<div>
								<button onClick={handleBuyNow} type="button" id="button_right" class="w-full h-[50px] rounded-md border-black border border-solid flex-none bg-black text-white mt-[25px] duration-300 hover:scale-105">Buy it now</button>
							</div>
							<div class=" h-[1px] bg-gray-300 mt-[30px]"></div>
							<div class="flex w-[335px] justify-between mt-[30px]">
								<div class="flex cursor-pointer">
									<p class="mt-[5px]"><BiGitCompare /></p>
									<p class="ml-2">Compare</p>
								</div>
								<div class="flex cursor-pointer">
									<p class="mt-[5px]"><BsQuestionCircle /></p>
									<p class="ml-2">Ask a question</p>
								</div>
								<div class="flex cursor-pointer">
									<p class="mt-[5px]"><BsShare /></p>
									<p class="ml-2">Share</p>
								</div>
							</div>
							<div class="w-full h-[110px] flex justify-center items-center bg-gray-50 rounded-lg mt-[35px]">
								<div class="text-center">
									<img class="mb-[15px]" src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/trustbag.png?v=1628329053&width=360" alt="image here" />
									<p><strong>Guarantee safe & secure checkout</strong></p>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
			<div>
				<div id="tabhead">

					<button ref={bt1} class="fontBu" onClick={() => display_Tab(bt1, desRef)} >Product description</button>
					<button ref={bt2} class="tabitem" onClick={() => display_Tab(bt2, reRef)}>Shipping & Return</button>
					<button ref={bt3} class="tabitem" onClick={() => display_Tab(bt3, polRef)}>Shipping policies</button>
				</div>
				<div class="w-78/100 h-[2px] bg-gray-300 m-auto mt-[20px] mb-[70px]"></div>
				<div class="mb-[165px]">
					<div ref={desRef} class="context space-y-6 bolck">
						<h2 class="font-medium text-2xl">The Iconic Silhouette</h2>
						<p class="text-slate-600 leading-7">At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil
						</p>
						<div class="flex justify-between"><img class="w-1/3" src="https://cdn.shopify.com/s/files/1/0561/2742/2636/files/customcontent3.jpg?v=1627958045" alt="imnage here"></img>
							<img class="w-1/3" src="https://cdn.shopify.com/s/files/1/0561/2742/2636/files/customcontent4.jpg?v=1627958045" alt="imnage here"></img>
							<img class="w-1/3" src="https://cdn.shopify.com/s/files/1/0561/2742/2636/files/customcontent2.jpg?v=1627958045" alt="imnage here"></img></div>
					</div>
					<div ref={reRef} class="context hidden space-y-24">
						<p class="text-slate-600">Shipping cost is based on weight. Just add products to your cart and use the Shipping Calculator to see the shipping price.
							We want you to be 100% satisfied with your purchase. Items can be returned or exchanged within 30 days of delivery.</p>
						<div class="flex w-49/50 justify-between">
							<div class="w-47/100"><img src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/7_d838b6ff-4af2-41c0-930c-89c02535bc2e.jpg?v=1633319827&width=720" alt="imnage here"></img>
							</div>
							<div class="w-44/100 table">
								<div class="space-y-5 table-cell align-middle">
									<h1 class="text-5xl ">Poplin Top With</h1>
									<h1 class="text-5xl ">Ruffle Trim</h1>
									<p class="text-slate-600 ">We believe in crafting pieces where sustainability and style go hand in hand. </p>
									<p class="text-slate-600">Made from materials like recycled cashmere and sust </p>
								</div>
							</div>
						</div>
					</div>

					<div ref={polRef} class="context hidden space-y-24">
						<p class="text-slate-600">Shipping cost is based on weight. Just add products to your cart and use the Shipping Calculator to see the shipping price.
							We want you to be 100% satisfied with your purchase. Items can be returned or exchanged within 30 days of delivery.</p>
						<div class="flex w-49/50 justify-between">
							<div class="w-47/100"><img src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/7_d838b6ff-4af2-41c0-930c-89c02535bc2e.jpg?v=1633319827&width=720" alt="imnage here"></img>
							</div>
							<div class="w-44/100 table">
								<div class="space-y-5 table-cell align-middle">
									<h1 class="text-5xl ">Poplin Top With</h1>
									<h1 class="text-5xl ">Ruffle Trim</h1>
									<p class="text-slate-600 ">We believe in crafting pieces where sustainability and style go hand in hand. </p>
									<p class="text-slate-600">Made from materials like recycled cashmere and sust </p>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>

	);
}

export default Index;