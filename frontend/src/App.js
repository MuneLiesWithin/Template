import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'

/* Components */
import Navbar from './components/layouts/Navbar'
import Footer from './components/layouts/Footer'
import Container from './components/layouts/Container'
import Message from './components/layouts/Message'

/* Pages */
import Login from './components/pages/Auth/Login'
import Register from './components/pages/Auth/Register'
import Home from './components/pages/Home'
import Profile from './components/pages/User/Profile'

/* Context */
import { UserProvider } from './context/UserContext'

function App() {
  return (
    <Router>
      <UserProvider>
      <Navbar />
      <Message />
      <Container>
        <Routes>
          <Route path='/register' element={<Register />} />
          <Route path='/login' element={<Login />} />
          <Route path='/user/profile' element={<Profile />} />
          <Route path='/' element={<Home />} />
        </Routes>
      </Container>
      <Footer />
      </UserProvider>
    </Router>
  );
}

export default App;
