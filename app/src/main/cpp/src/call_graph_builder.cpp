/**
 * IDA Pro M - Call Graph Builder
 * Constructs call graphs and control flow graphs for analyzed functions
 */

#include "idapro_engine.h"
#include <vector>
#include <unordered_map>
#include <set>
#include <queue>
#include <stack>
#include <algorithm>
#include <sstream>

namespace idapro {

// ============================================================================
// Call Graph Builder Implementation
// ============================================================================

class CallGraphBuilderImpl {
public:
    struct CallGraphNode {
        int functionId;
        uint64_t address;
        std::string name;
        
        // Edges: callees (outgoing calls)
        std::vector<int> calleeIds;  // Function IDs this function calls
        std::vector<int> callerIds;  // Function IDs that call this function
        
        // Metrics
        int inDegree = 0;   // Number of callers
        int outDegree = 0;  // Number of callees
        
        bool isLibraryFunction = false;
        bool isRecursive = false;
    };
    
    struct CallGraphEdge {
        int fromId;   // Caller function ID
        int toId;     // Callee function ID
        uint64_t fromAddress;  // Address of call instruction
        uint64_t toAddress;    // Address of target function (entry point)
        int callCount = 1;     // Multiple calls possible
    };
    
    explicit CallGraphBuilderImpl(const std::vector<Function>& functions)
        : functions_(functions) {}
    
    // Build complete call graph
    void build() {
        nodes_.clear();
        edges_.clear();
        
        // Create nodes for each function
        for (const auto& func : functions_) {
            CallGraphNode node;
            node.functionId = func.id;
            node.address = func.startAddress;
            node.name = func.getDisplayName();
            node.isLibraryFunction = (func.type == Function::Type::LIBRARY ||
                                       func.type == Function::Type::IMPORTED);
            
            nodes_[func.id] = node;
        }
        
        // Create edges based on call information
        for (const auto& callerFunc : functions_) {
            for (uint64_t calleeAddr : callerFunc.callees) {
                // Find callee function by entry address
                const Function* calleeFunc = findFunctionByAddress(calleeAddr);
                if (calleeFunc) {
                    CallGraphEdge edge;
                    edge.fromId = callerFunc.id;
                    edge.toId = calleeFunc->id;
                    edge.toAddress = calleeAddr;
                    
                    // Find call instruction address (approximate)
                    edge.fromAddress = findCallInstruction(callerFunc, calleeAddr);
                    
                    edges_.push_back(edge);
                    
                    // Update node degrees
                    nodes_[callerFunc.id].outDegree++;
                    nodes_[callerFunc.id].calleeIds.push_back(calleeFunc->id);
                    nodes_[calleeFunc->id].inDegree++;
                    nodes_[calleeFunc->id].callerIds.push_back(callerFunc.id);
                }
            }
        }
        
        // Detect recursive functions
        detectRecursion();
    }
    
    // Get graph in DOT format for visualization
    std::string toDotFormat() const {
        std::ostringstream oss;
        oss << "digraph CallGraph {\n";
        oss << "    rankdir=TB;\n";
        oss << "    node [shape=box, style=filled];\n";
        oss << "    edge [arrowhead=normal];\n\n";
        
        // Write nodes
        for (const auto& [id, node] : nodes_) {
            oss << "    \"" << node.name << "\" [";
            
            // Set color based on properties
            if (node.isLibraryFunction) {
                oss << "fillcolor=\"#E8F5E9\"";  // Green for library
            } else if (node.isRecursive) {
                oss << "fillcolor=\"#FFF3E0\"";  // Orange for recursive
            } else {
                oss << "fillcolor=\"#E3F2FD\"";  // Blue for normal
            }
            
            oss << ", label=\"" << node.name << "\\n(" 
                << node.inDegree << " in, " << node.outDegree << " out)\"];\n";
        }
        
        oss << "\n";
        
        // Write edges
        for (const auto& edge : edges_) {
            const auto& fromNode = nodes_.at(edge.fromId);
            const auto& toNode = nodes_.at(edge.toId);
            
            oss << "    \"" << fromNode.name << "\" -> \"" << toNode.name << "\"";
            
            if (edge.callCount > 1) {
                oss << " [label=\"" << edge.callCount << "\"]";
            }
            
            oss << ";\n";
        }
        
        oss << "}\n";
        return oss.str();
    }
    
    // Get root functions (entry points, not called by others)
    std::vector<const CallGraphNode*> getRootFunctions() const {
        std::vector<const CallGraphNode*> roots;
        
        for (const auto& [id, node] : nodes_) {
            if (node.inDegree == 0 && !node.isLibraryFunction) {
                roots.push_back(&node);
            }
        }
        
        return roots;
    }
    
    // Get leaf functions (don't call other non-library functions)
    std::vector<const CallGraphNode*> getLeafFunctions() const {
        std::vector<const CallGraphNode*> leaves;
        
        for (const auto& [id, node] : nodes_) {
            bool hasNonLibCallees = false;
            for (int calleeId : node.calleeIds) {
                auto it = nodes_.find(calleeId);
                if (it != nodes_.end() && !it->second.isLibraryFunction) {
                    hasNonLibCallees = true;
                    break;
                }
            }
            
            if (!hasNonLibCallees && !node.isLibraryFunction) {
                leaves.push_back(&node);
            }
        }
        
        return leaves;
    }
    
    // Calculate graph metrics
    struct GraphMetrics {
        int totalNodes = 0;
        int totalEdges = 0;
        double averageOutDegree = 0.0;
        double maxDepth = 0.0;
        int stronglyConnectedComponents = 0;
    };
    
    GraphMetrics calculateMetrics() const {
        GraphMetrics metrics;
        metrics.totalNodes = static_cast<int>(nodes_.size());
        metrics.totalEdges = static_cast<int>(edges_.size());
        
        if (!nodes_.empty()) {
            int totalOutDegree = 0;
            for (const auto& [id, node] : nodes_) {
                totalOutDegree += node.outDegree;
            }
            metrics.averageOutDegree = static_cast<double>(totalOutDegree) / 
                                        static_cast<double>(nodes_.size());
        }
        
        // Calculate maximum depth using BFS from root functions
        auto roots = getRootFunctions();
        std::unordered_map<int, int> depths;
        std::queue<std::pair<int, int>> bfsQueue;
        
        for (const auto* root : roots) {
            bfsQueue.push({root->functionId, 1});
            depths[root->functionId] = 1;
        }
        
        while (!bfsQueue.empty()) {
            auto [currentId, depth] = bfsQueue.front();
            bfsQueue.pop();
            
            metrics.maxDepth = std::max(metrics.maxDepth, static_cast<double>(depth));
            
            const auto& currentNode = nodes_.at(currentId);
            for (int calleeId : currentNode.calleeIds) {
                if (depths.find(calleeId) == depths.end() || 
                    depths[calleeId] < depth + 1) {
                    depths[calleeId] = depth + 1;
                    bfsQueue.push({calleeId, depth + 1});
                }
            }
        }
        
        return metrics;
    }

private:
    const std::vector<Function>& functions_;
    std::unordered_map<int, CallGraphNode> nodes_;
    std::vector<CallGraphEdge> edges_;
    
    const Function* findFunctionByAddress(uint64_t address) const {
        for (const auto& func : functions_) {
            if (func.startAddress == address) {
                return &func;
            }
        }
        return nullptr;
    }
    
    uint64_t findCallInstruction(const Function& caller, uint64_t calleeAddress) const {
        // Find the instruction that calls the given address
        for (const auto& bb : caller.basicBlocks) {
            for (const auto& insn : bb.instructions) {
                if (isCallInstruction(insn.type) &&
                    insn.branchTarget.has_value() &&
                    *insn.branchTarget == calleeAddress) {
                    return insn.address;
                }
            }
        }
        return 0;  // Not found
    }
    
    void detectRecursion() {
        // Simple recursion detection using DFS
        for (auto& [id, node] : nodes_) {
            std::set<int> visited;
            std::set<int> recursionStack;
            
            if (hasCycleDFS(id, visited, recursionStack)) {
                node.isRecursive = true;
            }
        }
    }
    
    bool hasCycleDFS(int nodeId, std::set<int>& visited, std::set<int>& recursionStack) const {
        visited.insert(nodeId);
        recursionStack.insert(nodeId);
        
        auto it = nodes_.find(nodeId);
        if (it == nodes_.end()) return false;
        
        for (int calleeId : it->second.calleeIds) {
            if (visited.find(calleeId) == visited.end()) {
                if (hasCycleDFS(calleeId, visited, recursionStack)) {
                    return true;
                }
            } else if (recursionStack.find(calleeId) != recursionStack.end()) {
                return true;  // Back edge found - cycle detected
            }
        }
        
        recursionStack.erase(nodeId);
        return false;
    }
};

// ============================================================================
// Control Flow Graph Builder
// ============================================================================

class CFGBuilderImpl {
public:
    explicit CFGBuilderImpl(Function& function)
        : function_(function) {}
    
    // Build CFG for a function
    void build() {
        function_.basicBlocks.clear();
        function_.adjacencyList.clear();
        
        // Step 1: Split instructions into basic blocks
        splitIntoBasicBlocks();
        
        // Step 2: Connect basic blocks with edges
        connectBasicBlocks();
        
        // Step 3: Compute dominators and other properties
        computeDominators();
        
        // Step 4: Calculate cyclomatic complexity
        function_.cyclomaticComplexity = computeCyclomaticComplexity();
    }
    
    // Export CFG as DOT format
    std::string toDotFormat() const {
        std::ostringstream oss;
        oss << "digraph CFG_" << function_.getDisplayName() << " {\n";
        oss << "    label=\"" << function_.getDisplayName() << "\\n"
            << "Complexity: " << function_.cyclomaticComplexity << "\";\n";
        oss << "    labelloc=t;\n";
        oss << "    rankdir=TD;\n";
        oss << "    node [shape=record, style=filled];\n\n";
        
        // Write basic block nodes
        for (const auto& bb : function_.basicBlocks) {
            std::string fillColor;
            if (bb.isEntry) {
                fillColor = "#E8F5E9";  // Green for entry
            } else if (bb.isExit) {
                fillColor = "#FFEBEE";  // Red for exit
            } else if (bb.isLoopHeader) {
                fillColor = "#FFF3E0";  // Orange for loop header
            } else {
                fillColor = "#E3F2FD";  // Blue for normal
            }
            
            oss << "    block" << bb.id << " [\n";
            oss << "        fillcolor=\"" << fillColor << "\",\n";
            oss << "        label=\"{" << bb.label() << "|\\n";
            
            // Add first few instructions
            size_t instrCount = std::min(bb.instructions.size(), size_t(5));
            for (size_t i = 0; i < instrCount; ++i) {
                const auto& insn = bb.instructions[i];
                oss << utils::formatAddress(insn.address) << ": " 
                    << insn.mnemonic << "\\n";
            }
            
            if (bb.instructions.size() > 5) {
                oss << "... (" << (bb.instructions.size() - 5) << " more)\\n";
            }
            
            oss << "}\"];\n";
        }
        
        oss << "\n";
        
        // Write edges
        for (const auto& [blockId, successors] : function_.adjacencyList) {
            const auto& fromBlock = function_.basicBlocks[blockId];
            for (int succId : successors) {
                const auto& toBlock = function_.basicBlocks[succId];
                
                // Determine edge type for coloring
                std::string color = "#49454F";  // Default gray
                
                // Check if this is a conditional branch
                if (fromBlock.successors.size() > 1) {
                    // Conditional branch - use different colors for taken/not-taken
                    if (succId == fromBlock.successors[0]) {
                        color = "#4CAF50";  // Green for fall-through/true
                    } else {
                        color = "#F44336";  // Red for branch/false
                    }
                }
                
                oss << "    block" << blockId << " -> block" << succId 
                    << " [color=\"" << color << "\"];\n";
            }
        }
        
        oss << "}\n";
        return oss.str();
    }

private:
    Function& function_;
    
    void splitIntoBasicBlocks() {
        std::vector<Instruction> allInstructions;
        
        // Collect all instructions sorted by address
        for (const auto& bb : function_.basicBlocks) {
            for (const auto& insn : bb.instructions) {
                allInstructions.push_back(insn);
            }
        }
        
        if (allInstructions.empty()) return;
        
        // Sort by address
        std::sort(allInstructions.begin(), allInstructions.end(),
                  [](const Instruction& a, const Instruction& b) {
                      return a.address < b.address;
                  });
        
        // Find leaders (start of basic blocks)
        std::set<uint64_t> leaders;
        leaders.insert(allInstructions[0].address);  // First instruction is always a leader
        
        for (const auto& insn : allInstructions) {
            // Target of branch/call is a leader
            if ((insn.isBranch || insn.isCall) && insn.branchTarget.has_value()) {
                leaders.insert(*insn.branchTarget);
            }
            
            // Instruction after branch/return is a leader
            if (insn.isBranch || insn.isReturn || insn.isTerminal) {
                uint64_t nextAddr = insn.address + insn.size;
                if (nextAddr > 0) {  // Valid address
                    leaders.insert(nextAddr);
                }
            }
        }
        
        // Create basic blocks
        int blockId = 0;
        BasicBlock currentBlock;
        currentBlock.id = blockId++;
        currentBlock.isEntry = (blockId == 1);
        
        for (const auto& insn : allInstructions) {
            if (leaders.count(insn.address) && !currentBlock.instructions.empty()) {
                // Start new basic block
                function_.basicBlocks.push_back(currentBlock);
                
                currentBlock = BasicBlock();
                currentBlock.id = blockId++;
                currentBlock.startAddress = insn.address;
            }
            
            if (currentBlock.instructions.empty()) {
                currentBlock.startAddress = insn.address;
            }
            
            currentBlock.instructions.push_back(insn);
            currentBlock.endAddress = insn.address + insn.size;
            insn.basicBlockId = currentBlock.id;
        }
        
        // Don't forget the last block
        if (!currentBlock.instructions.empty()) {
            currentBlock.isExit = true;  // Assume last block is exit
            function_.basicBlocks.push_back(currentBlock);
        }
    }
    
    void connectBasicBlocks() {
        // Build adjacency list based on control flow
        for (size_t i = 0; i < function_.basicBlocks.size(); ++i) {
            auto& bb = function_.basicBlocks[i];
            
            if (bb.instructions.empty()) continue;
            
            const auto& lastInsn = bb.instructions.back();
            
            if (lastInsn.isReturn || lastInsn.isTerminal) {
                // No successors - exit block
                bb.isExit = true;
            } else if (lastInsn.isBranch) {
                // Unconditional or conditional branch
                if (lastInsn.branchTarget.has_value()) {
                    // Find target basic block
                    int targetBlockId = findBlockContaining(*lastInsn.branchTarget);
                    if (targetBlockId >= 0) {
                        bb.successors.push_back(targetBlockId);
                        function_.adjacencyList[bb.id].push_back(targetBlockId);
                    }
                }
                
                // For conditional branches, also add fall-through successor
                if (lastInsn.isConditional) {
                    uint64_t nextAddr = lastInsn.address + lastInsn.size;
                    int nextBlockId = findBlockContaining(nextAddr);
                    if (nextBlockId >= 0) {
                        bb.successors.push_back(nextBlockId);
                        function_.adjacencyList[bb.id].push_back(nextBlockId);
                    }
                }
            } else {
                // Fall through to next block
                if (i + 1 < function_.basicBlocks.size()) {
                    int nextBlockId = function_.basicBlocks[i + 1].id;
                    bb.successors.push_back(nextBlockId);
                    function_.adjacencyList[bb.id].push_back(nextBlockId);
                } else {
                    bb.isExit = true;
                }
            }
            
            // Update predecessor lists
            for (int succId : bb.successors) {
                if (succId < static_cast<int>(function_.basicBlocks.size())) {
                    function_.basicBlocks[succId].predecessors.push_back(bb.id);
                }
            }
            
            function_.edgeCount += static_cast<int>(bb.successors.size());
        }
    }
    
    int findBlockContaining(uint64_t address) const {
        for (const auto& bb : function_.basicBlocks) {
            if (address >= bb.startAddress && address <= bb.endAddress) {
                return bb.id;
            }
        }
        return -1;
    }
    
    void computeDominators() {
        // Simplified dominator computation using iterative algorithm
        if (function_.basicBlocks.empty()) return;
        
        int n = static_cast<int>(function_.basicBlocks.size());
        
        // Initialize: entry block dominates itself
        std::vector<std::set<int>> domSets(n);
        domSets[0].insert(0);
        
        // Other blocks start with all blocks as potential dominators
        for (int i = 1; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                domSets[i].insert(j);
            }
        }
        
        // Iterate until stable
        bool changed = true;
        while (changed) {
            changed = false;
            
            for (int i = 1; i < n; ++i) {
                const auto& preds = function_.basicBlocks[i].predecessors;
                if (preds.empty()) continue;
                
                // Intersect dominator sets of predecessors
                std::set<int> newDomSet = domSets[preds[0]];
                
                for (size_t p = 1; p < preds.size(); ++p) {
                    std::set<int> intersection;
                    std::set_intersection(
                        newDomSet.begin(), newDomSet.end(),
                        domSets[preds[p]].begin(), domSets[preds[p]].end(),
                        std::inserter(intersection, intersection.begin())
                    );
                    newDomSet = intersection;
                }
                
                // Add self
                newDomSet.insert(i);
                
                if (newDomSet != domSets[i]) {
                    domSets[i] = newDomSet;
                    changed = true;
                }
            }
        }
        
        // Store results
        for (int i = 0; i < n; ++i) {
            function_.basicBlocks[i].dominators.assign(
                domSets[i].begin(), domSets[i].end()
            );
            
            // Find immediate dominator (dominator with highest post-order number)
            if (i > 0 && !domSets[i].empty()) {
                domSets[i].erase(i);  // Remove self
                if (!domSets[i].empty()) {
                    // The immediate dominator is the one that dominates this block
                    // but is dominated by all others that dominate this block
                    // Simplified: just take any dominator other than self
                    function_.basicBlocks[i].immediateDominator = *domSets[i].rbegin();
                }
            }
        }
    }
    
    int computeCyclomaticComplexity() const {
        // Cyclomatic complexity = E - N + 2P
        // Where E = edges, N = nodes, P = connected components (usually 1)
        int edges = function_.edgeCount;
        int nodes = static_cast<int>(function_.basicBlocks.size());
        
        return edges - nodes + 2;
    }
};

} // namespace idapro
