import { createSlice } from '@reduxjs/toolkit'

export const cartSlice = createSlice({
    name: 'cart',
    initialState: {
        cart: []
    },
    reducers: {
        add: (state, action) => {
            let contain = false
            state.cart.map((item, index) => {
                if (item.data.data.id == action.payload.data.id) contain = true
            })
            if (!contain) state.cart = [...state.cart, { data: action.payload }]
        },
        remove: (state, action) => {
            state.cart = state.cart.filter(item => item.data.data.id != action.payload)
        },
        upAmount: (state, action) => {
            console.log(action.payload);
            let arr = []
            state.cart.forEach(item => {
                if (item.data.data.id == action.payload) {
                    item.data.amount += 1
                }
                arr = [...arr, item]
            })
            state.cart = arr
        },
        downAmount: (state, action) => {
            let arr = []
            state.cart.forEach(item => {
                if (item.data.data.id == action.payload) {
                    item.data.amount -= 1
                }
                if (item.data.amount != 0) arr = [...arr, item]
            })
            state.cart = arr
        },
        resetCart: state => {
            state.cart = []
        },
    }
})

// Action creators are generated for each case reducer function
export const { add, remove, upAmount, downAmount, resetCart } = cartSlice.actions

export default cartSlice.reducer