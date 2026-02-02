/**
 * Lateryx Landing Page - Interactive JavaScript
 * ==============================================
 * Features:
 * - Scroll-triggered animations using Intersection Observer
 * - Animated number counters
 * - Smooth scrolling
 * - Graph visualization effects
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all modules
    initScrollAnimations();
    initNumberCounters();
    initSmoothScroll();
    initGraphAnimation();
    initNavbarScroll();
});

/**
 * Intersection Observer for scroll-triggered animations
 */
function initScrollAnimations() {
    const animatedElements = document.querySelectorAll('.animate-on-scroll');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Add staggered delay
                setTimeout(() => {
                    entry.target.classList.add('visible');
                }, index * 100);
                
                // Unobserve after animation
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    animatedElements.forEach(el => observer.observe(el));
}

/**
 * Animated number counters for stats section
 */
function initNumberCounters() {
    const counters = document.querySelectorAll('.stat-number[data-target]');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const counter = entry.target;
                const target = parseInt(counter.getAttribute('data-target'));
                animateCounter(counter, target);
                observer.unobserve(counter);
            }
        });
    }, { threshold: 0.5 });
    
    counters.forEach(counter => observer.observe(counter));
}

function animateCounter(element, target) {
    const duration = 2000; // 2 seconds
    const frameDuration = 1000 / 60; // 60fps
    const totalFrames = Math.round(duration / frameDuration);
    
    let frame = 0;
    const easeOutQuart = t => 1 - Math.pow(1 - t, 4);
    
    const animate = () => {
        frame++;
        const progress = easeOutQuart(frame / totalFrames);
        const current = Math.round(target * progress);
        
        element.textContent = current.toLocaleString();
        
        if (frame < totalFrames) {
            requestAnimationFrame(animate);
        } else {
            element.textContent = target.toLocaleString();
        }
    };
    
    animate();
}

/**
 * Smooth scrolling for anchor links
 */
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                const navHeight = document.querySelector('.navbar').offsetHeight;
                const targetPosition = targetElement.offsetTop - navHeight - 20;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

/**
 * Graph visualization animation
 */
function initGraphAnimation() {
    const graphNodes = document.querySelectorAll('.graph-node');
    const edges = document.querySelectorAll('.edge');
    
    // Add hover effects to nodes
    graphNodes.forEach(node => {
        node.addEventListener('mouseenter', () => {
            edges.forEach(edge => {
                edge.style.strokeWidth = '3';
                edge.style.filter = 'drop-shadow(0 0 5px rgba(139, 92, 246, 0.5))';
            });
        });
        
        node.addEventListener('mouseleave', () => {
            edges.forEach(edge => {
                edge.style.strokeWidth = '2';
                edge.style.filter = 'none';
            });
        });
    });
    
    // Animate breach alert
    const breachAlert = document.querySelector('.breach-alert');
    if (breachAlert) {
        setInterval(() => {
            breachAlert.style.transform = 'translateX(-50%) scale(1.02)';
            setTimeout(() => {
                breachAlert.style.transform = 'translateX(-50%) scale(1)';
            }, 200);
        }, 3000);
    }
}

/**
 * Navbar background on scroll
 */
function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    let lastScroll = 0;
    
    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 50) {
            navbar.style.background = 'rgba(10, 10, 15, 0.95)';
            navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.3)';
        } else {
            navbar.style.background = 'rgba(10, 10, 15, 0.8)';
            navbar.style.boxShadow = 'none';
        }
        
        lastScroll = currentScroll;
    });
}

/**
 * Add particle effect to hero section (optional enhancement)
 */
function createParticles() {
    const hero = document.querySelector('.hero');
    if (!hero) return;
    
    const particleCount = 30;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.cssText = `
            position: absolute;
            width: ${Math.random() * 3 + 1}px;
            height: ${Math.random() * 3 + 1}px;
            background: rgba(139, 92, 246, ${Math.random() * 0.3 + 0.1});
            border-radius: 50%;
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            animation: float ${Math.random() * 10 + 10}s linear infinite;
            pointer-events: none;
        `;
        hero.appendChild(particle);
    }
}

// Create particles after page load
setTimeout(createParticles, 500);

/**
 * Add typing effect to code blocks (subtle enhancement)
 */
function initTypingEffect() {
    const codeBlocks = document.querySelectorAll('.code-block code');
    
    codeBlocks.forEach(block => {
        const originalHTML = block.innerHTML;
        const text = block.textContent;
        
        block.innerHTML = '';
        block.style.opacity = '1';
        
        let charIndex = 0;
        const typeChar = () => {
            if (charIndex < text.length) {
                block.textContent += text[charIndex];
                charIndex++;
                setTimeout(typeChar, 10);
            } else {
                // Restore syntax highlighting
                block.innerHTML = originalHTML;
            }
        };
        
        // Start typing when visible
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                typeChar();
                observer.unobserve(block);
            }
        });
        
        observer.observe(block);
    });
}

// Optional: Enable typing effect
// initTypingEffect();

/**
 * Copy code to clipboard functionality
 */
function addCopyButtons() {
    const codeBlocks = document.querySelectorAll('.hero-code, .config-preview');
    
    codeBlocks.forEach(block => {
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-btn';
        copyButton.innerHTML = '📋';
        copyButton.setAttribute('aria-label', 'Copy code');
        copyButton.style.cssText = `
            position: absolute;
            top: 12px;
            right: 12px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            border-radius: 6px;
            padding: 8px 10px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        `;
        
        copyButton.addEventListener('mouseenter', () => {
            copyButton.style.background = 'rgba(255, 255, 255, 0.2)';
        });
        
        copyButton.addEventListener('mouseleave', () => {
            copyButton.style.background = 'rgba(255, 255, 255, 0.1)';
        });
        
        copyButton.addEventListener('click', async () => {
            const code = block.querySelector('code').textContent;
            try {
                await navigator.clipboard.writeText(code);
                copyButton.innerHTML = '✓';
                setTimeout(() => {
                    copyButton.innerHTML = '📋';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
        
        block.style.position = 'relative';
        block.appendChild(copyButton);
    });
}

// Add copy buttons after page load
setTimeout(addCopyButtons, 100);

/**
 * Mobile menu toggle (if needed)
 */
function initMobileMenu() {
    const navbar = document.querySelector('.navbar');
    const navLinks = document.querySelector('.nav-links');
    
    // Create hamburger button
    const hamburger = document.createElement('button');
    hamburger.className = 'hamburger';
    hamburger.innerHTML = '☰';
    hamburger.style.cssText = `
        display: none;
        background: none;
        border: none;
        color: white;
        font-size: 1.5rem;
        cursor: pointer;
    `;
    
    // Show on mobile
    if (window.innerWidth <= 768) {
        hamburger.style.display = 'block';
    }
    
    hamburger.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });
    
    document.querySelector('.nav-container').appendChild(hamburger);
    
    // Handle resize
    window.addEventListener('resize', () => {
        if (window.innerWidth <= 768) {
            hamburger.style.display = 'block';
        } else {
            hamburger.style.display = 'none';
            navLinks.classList.remove('active');
        }
    });
}

// Initialize mobile menu
initMobileMenu();

console.log('🛡️ Lateryx Landing Page Loaded');
