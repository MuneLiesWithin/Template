import { Link } from 'react-router-dom'
import styles from './Navbar.module.css'
import { useContext } from 'react'
import { Context } from '../../context/UserContext'

function Navbar() {
    const {authenticated, logout} = useContext(Context)

    return (
        <nav className={styles.navbar}>
            <div className={styles.navbar_logo}>
                <Link to="/">
                <h2>Template</h2>  
                </Link> 
            </div>
            <ul>
                {authenticated ? (
                    <>
                        <li>
                        <Link to='/user/profile'>Perfil</Link>
                        </li>
                        <li onClick={logout}>Sair</li>
                    </>
                    ) : (
                    <>
                        <li>
                            <Link to='/login'>Entrar</Link>
                        </li>
                        <li>
                            <Link to='/register'>Cadastrar</Link>
                        </li>
                    </>
                    )
                }     
            </ul>
        </nav>
    )
}

export default Navbar