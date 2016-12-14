package taintanalysis.inter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import soot.Body;
import soot.Local;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;

@SuppressWarnings("rawtypes")
public class IntraTaintAnalysisMain extends ForwardFlowAnalysis {

	Body body;
	FlowSet inval, outval;
	ArrayList<String> origVars = new ArrayList<String>();
	HashMap<String, HashMap<Integer, Boolean>> summary;
	// position of the tainted parameter in the method
	int paramPos;
	// does the method return a tainted value
	boolean taintReturn;
	
	@SuppressWarnings("unchecked")
	public IntraTaintAnalysisMain(UnitGraph g, HashMap summary, int paramPos) {
		super(g);
		body = g.getBody();
		this.summary = summary;
		this.paramPos = paramPos;
		// Initially we assuume that the method does not return a tainted value
		taintReturn = false;
		// carry out actual flow analysis 
		doAnalysis();
	}
	
	@Override
	// defining gen and kill set for a statement
	protected void flowThrough(Object in, Object unit, Object out) {
		inval = (FlowSet)in;
		outval = (FlowSet)out;
		Stmt stmt = (Stmt)unit;
		
		inval.copy(outval);
		
		// Kill and Gen operations
		
		// check if the statement is an assignment statment
		if(stmt instanceof AssignStmt) {
			String[] str = stmt.toString().split("[\\s\\<\\.]+");
			
			// if the assignment statement correspond to a print statement
			if(str.length > 7 && str[3].equalsIgnoreCase("lang") &&
					str[7].equalsIgnoreCase("printstream")) {
				
				outval.remove(((AssignStmt) stmt).getLeftOp().toString());
			}
			// if the assignment statement correspond to an invoke statement
			else if(str.length > 5 && (str[2].equalsIgnoreCase("virtualinvoke") ||
					str[2].equalsIgnoreCase("staticinvoke") || str[2].equalsIgnoreCase("specialinvoke"))) {
				//System.out.println("voila" + stmt);
				List<Value> args = stmt.getInvokeExpr().getArgs();
				String invokeExprName = stmt.getInvokeExpr().getMethod().getName();
				
				boolean tainted = false;
				
				HashMap<Integer, Boolean> funcSummary = summary.get(invokeExprName);
				
				Iterator it = funcSummary.entrySet().iterator();
				int i = 0;
				
				while(it.hasNext()) {
					@SuppressWarnings("unchecked")
					Map.Entry<Integer, Boolean> pair = (Map.Entry) it.next();
					
					if(inval.contains(args.get(i).toString()) && pair.getValue()) {
						tainted = true;
						break;
					}
					
					++i;
				}
				
				if(tainted) {
					outval.add(((AssignStmt) stmt).getLeftOp().toString());
				}
				else {
					outval.remove(((AssignStmt) stmt).getLeftOp().toString());
				}
			}
			else {
				String[] vars = ((AssignStmt) stmt).getRightOp().toString().split("[\\+\\-\\*\\/\\%]+");
				boolean tainted = false;
				
				for(int i = 0; i < vars.length; ++i) {
					vars[i] = vars[i].trim();
					
					if(inval.contains(vars[i])) {
						tainted = true;
						break;
					}
				}
				
				// if the operand on the LHS of assignment statement is not tainted, kill it
				if(!tainted) {
					outval.remove(((AssignStmt) stmt).getLeftOp().toString());
				}
				// else, generate it
				else {
					outval.add(((AssignStmt) stmt).getLeftOp().toString());
				}
			}
		}
		
		if(stmt instanceof ReturnStmt) {
			if(!taintReturn) {
				if(outval.contains(((ReturnStmt) stmt).getOp().toString())) {
					taintReturn = true;
				}
			}
		}
	}
	
	@Override
	protected void copy(Object source, Object dest) {
		FlowSet srcSet = (FlowSet)source;
		FlowSet	destSet = (FlowSet)dest;
		srcSet.copy(destSet);
		
	}
	
	@Override
	protected void merge(Object in1, Object in2, Object out) {
		FlowSet inval1=(FlowSet)in1;
		FlowSet inval2=(FlowSet)in2;
		FlowSet outSet=(FlowSet)out;
		// Taint analysis is a MAY analysis
		inval1.union(inval2, outSet);
	}
	
	
	@Override
	// Contents of the lattice element for the entry point
	protected Object entryInitialFlow() {
		ArraySparseSet arraySparseSet = new ArraySparseSet();
		
		// get method parameters
		ArrayList<String> params = getMethodParamsAndLocals(body.getMethod().getParameterCount());
		
		int i = 0;
		
		for(String param : params) {
			// Only the parameter at position 'paramPos' is tainted
			// so, add it to the content of the lattice element for the entry point
			if(i == paramPos) {
				arraySparseSet.add(param);
				break;
			}
			
			++i;
		}
		
		return arraySparseSet;
	}
	
	@Override
	// Contents of the lattice element for all the other points
	protected Object newInitialFlow() {
		return new ArraySparseSet();
	}
	
	// function to get parameters of a method
	private ArrayList<String> getMethodParamsAndLocals(int paramsCount) {
		ArrayList<String> params = new ArrayList<String>();
		ArrayList<String> locals = new ArrayList<String>();
		
		// loop through all local variables inside the soot representation of the java method
		// method parameters are also represented as local variables in soot representation of the java method
		for(Local local: body.getLocals()) {
			
			if(local.getName().equals("this")) {
				locals.add(local.getName());
			}
			else if(paramsCount == 0) {
				locals.add(local.getName());
				
				if(!local.getName().substring(0, 1).equals("$")) {
					origVars.add(local.getName());
				}
			}
			else {
				params.add(local.getName());
				origVars.add(local.getName());
				--paramsCount;
			}
		}
		
		return params;
	}
	
	public boolean getTaintReturn() {
		return taintReturn;
	}
}