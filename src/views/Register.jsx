import axios from 'axios'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ENDPOINT } from '../config/constans'

const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i
const initialForm = {
  email: 'docente@desafiolatam.com',
  password: '123456',
  rol: '',  // Inicializado como vacío
  lenguaje: ''  // Inicializado como vacío
}

const Register = () => {
  const navigate = useNavigate()
  const [user, setUser] = useState(initialForm)

  const handleUser = (event) => setUser({ ...user, [event.target.name]: event.target.value })

  const handleForm = (event) => {
    event.preventDefault()

    // Validación de campos: asegurarse de que no tengan los valores predeterminados
    if (
      !user.email.trim() ||
      !user.password.trim() ||
      user.rol === '' ||  // Comprobamos que el rol no esté vacío
      user.lenguaje === ''  // Comprobamos que el lenguaje no esté vacío
    ) {
      return window.alert('Todos los campos son obligatorios.')
    }

    // Validación del email
    if (!emailRegex.test(user.email)) {
      return window.alert('El formato del email no es correcto!')
    }

    // Enviar la solicitud para registrar el usuario
    axios.post(ENDPOINT.users, user)
      .then(() => {
        window.alert('Usuario registrado con éxito 😀.')
        navigate('/login')
      })
      .catch(({ response: { data } }) => {
        // Mostrar mensaje de error dependiendo de la respuesta
        console.error(data)
        if (data.error) {
          window.alert(`${data.error} 🙁.`) // Si el error está en la propiedad `error`, mostrarlo
        } else {
          window.alert('Ocurrió un error desconocido 🙁.') // Para errores que no tengan un mensaje claro
        }
      })
  }

  useEffect(() => {
    if (window.sessionStorage.getItem('token')) {
      navigate('/perfil')
    }
  }, [])

  return (
    <form onSubmit={handleForm} className='col-10 col-sm-6 col-md-3 m-auto mt-5'>
      <h1>Registrar nuevo usuario</h1>
      <hr />
      <div className='form-group mt-1'>
        <label>Email address</label>
        <input
          value={user.email}
          onChange={handleUser}
          type='email'
          name='email'
          className='form-control'
          placeholder='Enter email'
        />
      </div>
      <div className='form-group mt-1'>
        <label>Password</label>
        <input
          value={user.password}
          onChange={handleUser}
          type='password'
          name='password'
          className='form-control'
          placeholder='Password'
        />
      </div>
      <div className='form-group mt-1'>
        <label>Rol</label>
        <select
          value={user.rol}
          onChange={handleUser}
          name='rol'
          className='form-select'
        >
          <option value=''>Seleccione un rol</option>  {/* Cambiado para que el valor sea vacío */}
          <option value='Full Stack Developer'>Full Stack Developer</option>
          <option value='Frontend Developer'>Frontend Developer</option>
          <option value='Backend Developer'>Backend Developer</option>
        </select>
      </div>
      <div className='form-group mt-1'>
        <label>lenguaje</label>
        <select
          value={user.lenguaje}
          onChange={handleUser}
          name='lenguaje'
          className='form-select'
        >
          <option value=''>Seleccione un lenguaje</option>  {/* Cambiado para que el valor sea vacío */}
          <option value='JavaScript'>JavaScript</option>
          <option value='Python'>Python</option>
          <option value='Ruby'>Ruby</option>
        </select>
      </div>
      <button type='submit' className='btn btn-light mt-3'>Registrarme</button>
    </form>
  )
}

export default Register
