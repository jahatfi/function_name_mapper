// Sample usage:
// ./joern --script dump_call_graph.sc --param cFile=/layers.c --param projectName=layers --param outFile=graph_a.json

import java.io._

@main def exec(cFile: String, projectName: String, outFile: String) = {
   importCode(cFile, projectName)

   
   val callGraph = cpg.method.filterNot(_.name.startsWith("<operator>")).map { method =>
    val callees = method.call
        .filterNot(_.name.startsWith("<operator>"))  // Exclude operator calls
        .map(_.name)
        .distinct
        .sorted

    method.fullName -> callees
    }.toMap.toSeq.sortWith(_._1 < _._1)

    val pw = new PrintWriter(new java.io.File(outFile))
    pw.write(callGraph.toJson)
    pw.close
}
