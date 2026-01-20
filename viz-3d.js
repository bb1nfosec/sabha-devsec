// ============================================================================
// SABHA 3D Visualization Engine
// Three.js Attack Surface Maps & Cytoscape.js Knowledge Graphs
// ============================================================================

class Visualization3D {
    constructor() {
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.cytoscapeInstance = null;
    }

    // ========================================================================
    // 3D Attack Surface Visualization (Three.js)
    // ========================================================================

    /**
     * Initialize 3D scene for attack surface visualization
     * @param {string} containerId - DOM element ID
     */
    init3DScene(containerId) {
        const container = document.getElementById(containerId);
        if (!container || typeof THREE === 'undefined') {
            console.warn('Three.js not available or container not found');
            return;
        }

        // Scene setup
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x0f172a); // Dark background

        // Camera setup
        this.camera = new THREE.PerspectiveCamera(
            75,
            container.clientWidth / container.clientHeight,
            0.1,
            1000
        );
        this.camera.position.z = 50;

        // Renderer setup
        this.renderer = new THREE.WebGLRenderer({ antialias: true });
        this.renderer.setSize(container.clientWidth, container.clientHeight);
        container.appendChild(this.renderer.domElement);

        // Lighting
        const ambientLight = new THREE.AmbientLight(0x404040, 2);
        this.scene.add(ambientLight);

        const pointLight = new THREE.PointLight(0x10b981, 1, 100);
        pointLight.position.set(0, 10, 10);
        this.scene.add(pointLight);

        // Grid helper
        const gridHelper = new THREE.GridHelper(100, 20, 0x475569, 0x334155);
        this.scene.add(gridHelper);

        return this;
    }

    /**
     * Render 3D attack surface from findings
     * @param {Array} findings - Vulnerability findings
     * @param {Object} attackGraph - Attack graph data
     */
    render3DAttackSurface(findings, attackGraph) {
        if (!this.scene) {
            console.error('3D scene not initialized');
            return;
        }

        // Clear existing objects
        while (this.scene.children.length > 0) {
            this.scene.remove(this.scene.children[0]);
        }

        // Re-add lighting and grid
        const ambientLight = new THREE.AmbientLight(0x404040, 2);
        this.scene.add(ambientLight);
        const pointLight = new THREE.PointLight(0x10b981, 1, 100);
        pointLight.position.set(0, 10, 10);
        this.scene.add(pointLight);
        const gridHelper = new THREE.GridHelper(100, 20, 0x475569, 0x334155);
        this.scene.add(gridHelper);

        // Group findings by domain
        const domainMap = {};
        findings.forEach(f => {
            if (!domainMap[f.domain]) domainMap[f.domain] = [];
            domainMap[f.domain].push(f);
        });

        // Create 3D clusters for each domain
        const domains = Object.keys(domainMap);
        const radius = 20;

        domains.forEach((domain, idx) => {
            const angle = (idx / domains.length) * Math.PI * 2;
            const x = Math.cos(angle) * radius;
            const z = Math.sin(angle) * radius;

            this.createDomainCluster(domainMap[domain], x, 0, z, domain);
        });

        // Create connections for attack paths
        if (attackGraph && attackGraph.criticalPaths) {
            attackGraph.criticalPaths.forEach(path => {
                // Draw path visualization (simplified)
                this.createPathLine(path);
            });
        }

        // Animation loop
        this.animate();
    }

    /**
     * Create a 3D cluster for a domain
     */
    createDomainCluster(findings, x, y, z, domainName) {
        // Create group for this domain
        const group = new THREE.Group();
        group.position.set(x, y, z);

        // Color based on severity distribution
        const critical = findings.filter(f => f.severity === 'critical').length;
        const high = findings.filter(f => f.severity === 'high').length;
        const color = critical > 0 ? 0xef4444 :
            high > 0 ? 0xf59e0b :
                0x10b981;

        // Create main sphere representing the domain
        const geometry = new THREE.SphereGeometry(2, 32, 32);
        const material = new THREE.MeshPhongMaterial({
            color: color,
            emissive: color,
            emissiveIntensity: 0.2,
            transparent: true,
            opacity: 0.8
        });
        const sphere = new THREE.Mesh(geometry, material);
        group.add(sphere);

        // Add smaller spheres for each critical/high finding
        findings.filter(f => f.severity === 'critical' || f.severity === 'high')
            .slice(0, 10)
            .forEach((finding, idx) => {
                const smallGeometry = new THREE.SphereGeometry(0.5, 16, 16);
                const smallColor = finding.severity === 'critical' ? 0xdc2626 : 0xf97316;
                const smallMaterial = new THREE.MeshPhongMaterial({
                    color: smallColor,
                    emissive: smallColor,
                    emissiveIntensity: 0.3
                });
                const smallSphere = new THREE.Mesh(smallGeometry, smallMaterial);

                // Position around main sphere
                const angle = (idx / 10) * Math.PI * 2;
                const distance = 4;
                smallSphere.position.set(
                    Math.cos(angle) * distance,
                    (idx % 3 - 1) * 2,
                    Math.sin(angle) * distance
                );

                group.add(smallSphere);
            });

        // Add label (using sprite - simplified for demo)
        const labelCanvas = this.createTextLabel(domainName, findings.length);
        const labelTexture = new THREE.CanvasTexture(labelCanvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: labelTexture });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.position.y = 4;
        sprite.scale.set(4, 2, 1);
        group.add(sprite);

        // Add pulsing animation
        group.userData = {
            originalScale: 1,
            pulsePhase: Math.random() * Math.PI * 2
        };

        this.scene.add(group);
    }

    /**
     * Create attack path line
     */
    createPathLine(path) {
        // Simplified: just draw a line for visual effect
        const material = new THREE.LineBasicMaterial({
            color: 0xef4444,
            linewidth: 2,
            opacity: 0.6,
            transparent: true
        });

        // Create curved path
        const curve = new THREE.CatmullRomCurve3([
            new THREE.Vector3(-10, 0, -10),
            new THREE.Vector3(0, 5, 0),
            new THREE.Vector3(10, 0, 10)
        ]);

        const points = curve.getPoints(50);
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const line = new THREE.Line(geometry, material);

        this.scene.add(line);
    }

    /**
     * Create text label canvas
     */
    createTextLabel(text, count) {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = 256;
        canvas.height = 128;

        context.fillStyle = 'rgba(15, 23, 42, 0.9)';
        context.fillRect(0, 0, canvas.width, canvas.height);

        context.fillStyle = '#ffffff';
        context.font = 'bold 24px Inter';
        context.textAlign = 'center';
        context.fillText(text, canvas.width / 2, 50);

        context.font = '18px Inter';
        context.fillStyle = '#94a3b8';
        context.fillText(`${count} findings`, canvas.width / 2, 80);

        return canvas;
    }

    /**
     * Animation loop - OPTIMIZED FOR BETTER UX
     */
    animate() {
        if (!this.renderer || !this.scene || !this.camera) return;

        requestAnimationFrame(() => this.animate());

        // IMPROVED: 5x SLOWER, smoother camera rotation
        const time = Date.now() * 0.00002; // Was 0.0001, now 5x slower
        this.camera.position.x = Math.cos(time) * 50;
        this.camera.position.y = 20 + Math.sin(time * 0.3) * 3; // Gentle vertical movement
        this.camera.position.z = Math.sin(time) * 50;
        this.camera.lookAt(0, 0, 0);

        // IMPROVED: Subtle pulse effect (50% less aggressive)
        this.scene.children.forEach(child => {
            if (child.userData && child.userData.pulsePhase !== undefined) {
                const pulse = Math.sin(time * 4 + child.userData.pulsePhase) * 0.05 + 1; // Was 0.1, now 0.05
                child.scale.set(pulse, pulse, pulse);
            }
        });

        this.renderer.render(this.scene, this.camera);
    }

    /**
     * Resize handler
     */
    resize(width, height) {
        if (this.camera && this.renderer) {
            this.camera.aspect = width / height;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(width, height);
        }
    }

    // ========================================================================
    // Cytoscape.js Knowledge Graph Visualization
    // ========================================================================

    /**
     * Initialize Cytoscape graph
     * @param {string} containerId - DOM element ID
     */
    initCytoscapeGraph(containerId) {
        if (typeof cytoscape === 'undefined') {
            console.warn('Cytoscape.js not available');
            return;
        }

        this.cytoscapeInstance = cytoscape({
            container: document.getElementById(containerId),

            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': 'data(color)',
                        'label': 'data(label)',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'font-size': '12px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'color': '#ffffff',
                        'text-outline-color': '#000000',
                        'text-outline-width': 2
                    }
                },
                {
                    selector: 'node.critical',
                    style: {
                        'background-color': '#ef4444',
                        'border-width': 3,
                        'border-color': '#dc2626'
                    }
                },
                {
                    selector: 'node.high',
                    style: {
                        'background-color': '#f59e0b',
                        'border-width': 2,
                        'border-color': '#d97706'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#64748b',
                        'target-arrow-color': '#64748b',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'opacity': 0.6
                    }
                },
                {
                    selector: 'edge.attack-chain',
                    style: {
                        'line-color': '#ef4444',
                        'target-arrow-color': '#ef4444',
                        'width': 3,
                        'opacity': 0.8
                    }
                }
            ],

            layout: {
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 30,
                randomize: false,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            }
        });

        return this;
    }

    /**
    * Render attack graph using Cytoscape
     * @param {Object} attackGraph - Attack graph with nodes and edges
     */
    renderAttackGraph(attackGraph) {
        if (!this.cytoscapeInstance) {
            console.error('Cytoscape not initialized');
            return;
        }

        const elements = [];

        // Add nodes
        attackGraph.nodes.forEach(node => {
            const severityColors = {
                critical: '#ef4444',
                high: '#f59e0b',
                medium: '#f59e0b',
                low: '#10b981'
            };

            elements.push({
                data: {
                    id: node.id.toString(),
                    label: node.label.substring(0, 30),
                    color: severityColors[node.severity] || '#64748b',
                    size: node.severity === 'critical' ? 60 : 40,
                    severity: node.severity,
                    type: node.type
                },
                classes: node.severity
            });
        });

        // Add edges
        attackGraph.edges.forEach((edge, idx) => {
            elements.push({
                data: {
                    id: `edge-${idx}`,
                    source: edge.source.toString(),
                    target: edge.target.toString(),
                    weight: edge.weight || 1
                },
                classes: edge.type === 'attack-chain' ? 'attack-chain' : ''
            });
        });

        this.cytoscapeInstance.elements().remove();
        this.cytoscapeInstance.add(elements);
        this.cytoscapeInstance.layout({
            name: 'cose',
            animate: true,
            animationDuration: 1000
        }).run();

        // Add click handlers
        this.cytoscapeInstance.on('tap', 'node', (event) => {
            const node = event.target;
            console.log('Clicked node:', node.data());
            // Could show details panel here
        });
    }

    /**
     * Highlight critical attack paths
     * @param {Array} paths - Critical paths from ML engine
     */
    highlightCriticalPaths(paths) {
        if (!this.cytoscapeInstance) return;

        // Reset all edges
        this.cytoscapeInstance.edges().removeClass('attack-chain');

        // Highlight first critical path
        if (paths.length > 0) {
            const path = paths[0];
            // Implementation would traverse path and highlight edges
            console.log('Highlighting path:', path);
        }
    }
}

// Export
if (typeof window !== 'undefined') {
    window.Visualization3D = Visualization3D;
    console.log('%c🎨 SABHA 3D Visualization Module Loaded', 'color: #8b5cf6; font-weight: bold;');
}
