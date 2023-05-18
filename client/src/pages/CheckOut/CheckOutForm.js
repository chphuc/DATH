import { useState, useEffect } from 'react'
import axios from '../../api'
import axiosR from 'axios'
import Select from 'react-select';

import CheckOutInput from "./CheckOutInput"

import { Link, useNavigate } from 'react-router-dom'
import { useSelector, useDispatch } from 'react-redux'

import { RiArrowLeftSLine } from 'react-icons/ri';

import { toast } from 'react-toastify';

import { useSocket } from '../../hooks'

const CheckOutForm = () => {
	const navigate = useNavigate()
	const user = useSelector(state => state.user)
	const socket = useSocket()

	const optionsAddress = [{ label: "New Address", value: "0" }]

	const selectStyle = "font-medium text-sm"

	//cart
	const [total, setTotal] = useState(0)
	const [itemCart, setItemCart] = useState([])

	const [curOptionProvince, setCurOptionProvince] = useState()
	const [curOptionDistrict, setCurOptionDistrict] = useState()
	const [curOptionWard, setCurOptionWard] = useState()

	const [orderValue, setOrderValue] = useState({
		optionAddress: "0",
		address: '',
		firstName: '',
		lastName: '',
		note: '',
	})
	const [provinceList, setProvinceList] = useState([])
	const [districtList, setDistrictList] = useState([])
	const [wardList, setWardList] = useState([])

	const onClickProvince = () => {
		if(provinceList.length) return
		axiosR.get('https://provinces.open-api.vn/api/p/')
			.then(res => {
				const response = res.data
				let curArr = []
				response.map(item => {
					curArr.push({ label: item.name, value: item.code })
				})
				setProvinceList(curArr)
			})
	}

	const onChangeProvinceValue = (provinceCode) => {
		setDistrictList([])
		setWardList([])
		axiosR.get(`https://provinces.open-api.vn/api/p/${provinceCode}?depth=2`)
			.then(res => {
				const response = res.data.districts
				let curArr = []
				response.map(item => {
					curArr.push({ label: item.name, value: item.code })
				})
				setDistrictList(curArr)
			})
	}

	const onChangeDistrictValue = (districtCode) => {
		axiosR.get(`https://provinces.open-api.vn/api/d/${districtCode}?depth=2`)
			.then(res => {
				const response = res.data.wards
				let curArr = []
				response.map(item => {
					curArr.push({ label: item.name, value: item.code })
				})
				setWardList(curArr)
			})
	}

	const handleOnchangeInput = (e) => {
		setOrderValue((prev) => ({
			...prev,
			[e.target.name]: e.target.value
		}))
	}

	//update total cart
	let items = useSelector(state => state.cart.cart)

	useEffect(() => {
		setItemCart(items)
		let temp = 0
		items.forEach(item => temp += +item.data.data.price * +item.data.amount)
		setTotal(temp);
	}, [items])

	const notifyErrorConfirm = () => toast.error('Missing data!', {
		position: "top-right",
		autoClose: 1000,
		hideProgressBar: false,
		closeOnClick: true,
		pauseOnHover: true,
		draggable: true,
		progress: undefined,
		theme: "light",
	});

	const notifySuccessConfirm = () => toast.success('Order success!', {
		position: "top-right",
		autoClose: 1000,
		hideProgressBar: false,
		closeOnClick: true,
		pauseOnHover: true,
		draggable: true,
		progress: undefined,
		theme: "light",
	});

	const confirmOrder = () => {
		if(!curOptionProvince || !curOptionDistrict || !curOptionWard || !orderValue.address || !orderValue.lastName) {
			notifyErrorConfirm()
			return
		}
		const products = []
		itemCart.map(item => products.push(
			{
				productId: item.data.data.id,
				quantity: item.data.amount,
				name: item.data.data.name,
				price: item.data.data.price,
				type: item.data.data.type,
			}
		))
		axios.post("/order/createOrder",
			{
				totalAmount: total,
				products: products,
				address: `${orderValue.address}, ${curOptionWard.label}, ${curOptionDistrict.label}, ${curOptionProvince.label}`,
				note: orderValue.note
			},
			{ withCredentials: true }
		)
			.then(res => {
				console.log(res)
				socket.emit('newOrder')
			})
			.catch(err => console.log(err))
		notifySuccessConfirm()
		navigate("/")
	}

	return (
		<div className="lg:pr-10">
			<p className="text-2xl pt-4 lg:pt-0 pb-4">Shipping address</p>
			<div className="mb-6">
				<Select
					options={optionsAddress}
					defaultValue={optionsAddress[0]}
					onChange={e => setOrderValue((prev) => ({ ...prev, optionAddress: e.value }))}
					className={selectStyle}
				/>
			</div>
			<div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-4 mb-6">
				<div>
					<p className="mb-1 font-medium">Province</p>
					<div onClick={onClickProvince}>
						<Select
							options={provinceList}
							onChange={(e) => {
								setCurOptionProvince({ label: e.label, value: e.value })
								onChangeProvinceValue(e.value)
							}}
							value={curOptionProvince}
							className={selectStyle}
						/>
					</div>
				</div>
				<div>
					<p className="mb-1 font-medium">District</p>
					<Select
						options={districtList}
						onChange={(e) => {
							setCurOptionDistrict({ label: e.label, value: e.value })
							onChangeDistrictValue(e.value)
						}}
						value={curOptionDistrict}
						className={selectStyle}
					/>
				</div>
				<div>
					<p className="mb-1 font-medium">Ward</p>
					<Select
						options={wardList}
						onChange={(e) => setCurOptionWard({ label: e.label, value: e.value })}
						value={curOptionWard}
						className={selectStyle}
					/>
				</div>
			</div>
			<div className="mb-6">
				<CheckOutInput name="address" value={orderValue.address} placeholder="Address" onChange={handleOnchangeInput} />
			</div>
			<div className="grid grid-cols-2 gap-4 mb-6">
				<CheckOutInput name="firstName" value={orderValue.firstName} placeholder="First name (optional)" onChange={handleOnchangeInput} />
				<CheckOutInput name="lastName" value={orderValue.lastName} placeholder="Last name" onChange={handleOnchangeInput} />
			</div>
			<div className="">
				<CheckOutInput name="note" value={orderValue.note} placeholder="Note (optional)" onChange={handleOnchangeInput} />
			</div>
			<div className="flex items-center justify-between py-3 lg:mt-20">
				<div className="flex items-center text-sky-600 cursor-pointer">
					<span className="text-2xl"><RiArrowLeftSLine /></span>
					<Link to="/">
						<p className="">Return to shipping</p>
					</Link>
				</div>
				<button onClick={confirmOrder} className="text-white bg-sky-700 p-4 rounded-lg">
					Cofirm order
				</button>
			</div>
		</div>
	)
}

export default CheckOutForm