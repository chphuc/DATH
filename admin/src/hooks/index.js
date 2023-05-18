import { useContext } from 'react'
import SocketContext from '../contexts/socket'

export function useSocket() {
  const socket = useContext(SocketContext)
  return socket
}