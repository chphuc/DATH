import { useEffect } from 'react'

import CheckOutForm from './CheckOutForm'
import CheckOutSummaryItem from './CheckOutSummaryItem'

import { useNavigate } from 'react-router-dom'
import { useSelector, useDispatch } from 'react-redux'
const Index = () => {
    const user = useSelector(state => state.user)
    const navigate = useNavigate()
    
    useEffect(() => {
        if (!user.user) navigate("/")
    }, [])
    return (
        <div className="flex lg:flex-row-reverse flex-wrap px-3 lg:pt-4 lg:px-12">
            <div className="w-full lg:w-2/5">
                <CheckOutSummaryItem />
            </div>
            <div className="w-full lg:w-3/5">
                <CheckOutForm />
            </div>
        </div>
    )
}

export default Index