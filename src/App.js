import React from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Projects from './components/Projects';
import Skills from './components/Skills';
import Resume from './components/Resume';
import Contact from './components/Contact';
import Footer from './components/Footer';

function App() {
    return (
        <div>
            <Navbar />
            <Hero />
            <Projects />
            <Skills />
            <Resume />
            <Contact />
            <Footer />
        </div>
    );
}

export default App;