using Xunit;

// Los asserts mutan estado compartido (BFLA borra usuarios, IDOR/BOLA tocan órdenes) y leen un app.log
// común: en paralelo producen veredictos intermitentes. xunit.runner.json no se copiaba a la salida, por
// lo que parallelizeTestCollections=false nunca se aplicaba; el atributo lo garantiza en el ensamblado.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
