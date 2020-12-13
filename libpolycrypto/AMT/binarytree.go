
package AMT


/**
 * Base class used to represent a full binary tree.
 * Leaves are at level 0.
 * TODO: Should change to q-ary tree (for time/space trade-off)
 */

    /** 
     * tree[k][i] is the ith node at level k in the tree (k = 0 is the last level with leaves)
     */

    /**
     * WARNING: Lambdas that 'capture' variables cannot be passed as arguments where a function pointer is expected. 
     * std::function must be used instead to pass in a lambda.
     */
    //typedef void (*ComputeNodeFunc)(size_t, size_t);  
   

    /**
     * Allocates a tree capable of storing the specified # of leaves.
     *
     * @param maxLevel  instead of creating a full tree with a root node, stops creating nodes past   
     *                  this level, resulting in a forest of trees, each with 2^maxLevel leaves
     */
    func allocateTree(numLeaves size_t ,  maxLevel size_t) {
        testAssertIsPowerOfTwo(numLeaves)

        /**
         * Height of tree in # of levels, where levels are counted as nodes (not as edges)
         * For example, when numLeaves = 2, height is 2.
         * Or, when numLeaves = 3 or 4, height is 3.
         * Or, when numLeaves = 5, 6, 7 or 8, height is 4.
         * In general, height is ceil(log2(numLeaves)) + 1.
         */
        maxHeight := log2ceil(numLeaves) + 1)
        if(maxLevel >= maxHeight) {
            
            fmt.Println("Invalid max level");
        }

        numLevels := maxLevel + 1;
        tree.resize(numLevels);
        tree[0].resize(numLeaves);
        
        for(k := 1; k < numLevels; k++) {
            tree[k].resize(tree[k-1].size() / 2);
        }
        
        // Check the root level has size 1
        assertEqual(tree[maxLevel].size(), numLeaves / (1u << maxLevel));
    }

    size_t getNumLeaves() const {
        return tree[0].size();
    }
    
    /**
     * Returns the number of levels in the tree (e.g., a one-node tree has 1 level).
     */
    //size_t getNumLevels() const {
    //    return tree.size();
    //}

    /**
     * Returns the path of nodes starting at the specified leaf all the way up to the root.
     * index 0 will store leaves and higher indices will store internal nodes.
     */
    func getPathFromLeaf(size_t leafIdx) const {
        std::vector<TreeNode> nodes;
        logtrace << "Fetching path for " << leafIdx << endl;
        for(auto& lvl : tree) {
            assertValidIndex(leafIdx, lvl);

            logtrace << "Pushing one node" << endl;
            nodes.push_back(lvl[leafIdx]);

            leafIdx /= 2;
        }
        return nodes;
    }
    // TODO: maybe add a pathExec() that executes a function for each node on the path? 

    /**
     * Pre-order traversal of the tree: (root, left child, right child)
     * Used when computing quotients in the tree and when committing to polynomials in the tree.
     */
    func traversePreorder(const ComputeNodeFunc& func) {
        assertStrictlyGreaterThan(tree.size(), 0);

        size_t rootLevel = tree.size() - 1;
        size_t numRoots =  tree.back().size();
        for(size_t i = 0; i < numRoots; i++)
            traversePreorder(rootLevel, i, func);
    }

    func traversePreorder(size_t k, size_t idx, const ComputeNodeFunc& func) {
        func(k, idx);
        
        // if we haven't reached the last level yet,
        if(k > 0) {
            traversePreorder(k - 1, 2*idx, func);         // go left
            if(2*idx + 1 < tree[k - 1].size()) {          // and, if you can,
                traversePreorder(k - 1, 2*idx + 1, func); // go right
            }
        }
    }
};

} 
