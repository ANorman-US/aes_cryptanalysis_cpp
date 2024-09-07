//Alexander Norman
//AES Cryptanalysis
#include ".\\headers\\aes.h"
#include ".\\headers\\huffman.h"
#include ".\\headers\\markov.h"
#include ".\\headers\\crypto.h"
#include <iostream>
#include <array>
#include <set>
#include <random>
#include <cmath>
#include <chrono>
#include <thread>
#include <mutex>
#include <queue>

using namespace std;

//const int NUM_PLAINTEXTS = 100'000;
//const int NUM_KEYS = 1'000'000;
const int NUM_PLAINTEXTS = 1;
const int NUM_KEYS = 1;
const int POPULATION_SIZE = 1000;
const double MUTATION_RATE = 0.05;
const double EPSILON = 1e-8;

array<unsigned char, 16> GLOBAL_KEY;

struct Individual{
    array<unsigned char, 16> key;
    double fitness;

    bool operator<(const Individual &other) const{
        return fitness > other.fitness;
    }
};

double calculateFitness(const array<unsigned char, 16> &, const array<array<double, 2>,2> &);
void initPop(int, array<Individual, POPULATION_SIZE> &, const array<array<double,2>,2> &);
void geneticAlgorithm(array<Individual, POPULATION_SIZE>&, const double&, const array<array<double, 2>,2> &, const array<unsigned char, 16>&, const array<unsigned char, 16>&);
bool isGoal(const array<unsigned char, 16>&, const array<unsigned char, 16> &, const array<unsigned char, 16> &);

int main()
{
    set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    Crypto::generateRandom128Bit(setPlainTexts, NUM_PLAINTEXTS);
    Crypto::generateRandom128Bit(setKeys, NUM_KEYS);

    AES aes;
    array<unsigned char, 16> state;
    array<unsigned char, 16> cipherText;
    array<array<double, 2>, 2> tMatrixControl;
    
    for(const auto &plainText : setPlainTexts)
    {
        for(const auto &key : setKeys)
        {
            GLOBAL_KEY = key;
            state = plainText;
            aes.encrypt(state, key);
            cipherText = state;
            Crypto::encodeText(state, plainText);
            Huffman huffman(state);
            Markov::generateMarkovTransitionMatrix(huffman.getHuffmanCodes(), tMatrixControl);

            //init population
            array<Individual, POPULATION_SIZE> population;
            initPop(POPULATION_SIZE, population, tMatrixControl);
            cout << "Key is \n";
            for(int i=0;i<16;i++)
                cout << (int) key[i];
            cout << endl;
            geneticAlgorithm(population, MUTATION_RATE, tMatrixControl, plainText, cipherText);


        }
    }

    return 0;
}

void geneticAlgorithm(array<Individual, POPULATION_SIZE> &population, const double& mutationRate, const array<array<double, 2>,2> &tMatrixControl, const array<unsigned char, 16> &plainText, const array<unsigned char, 16> &cipherText)
{
    auto start = chrono::high_resolution_clock::now();

    int generationNum = 0;
    Individual bestChild;
    bestChild.fitness = INT_MAX;

    bool found = false;
    while(!found)
    {   
        cout << generationNum << "********************************" << endl;
        
        double totalFitness = 0.0;

        for(int i=0;i<POPULATION_SIZE;i++)
            totalFitness += (1.0 / max(population[i].fitness, EPSILON));//epsilon to avoid division by 0
        
        array<double, POPULATION_SIZE> individualProbability;
        individualProbability[0] = (1.0 / max(population[0].fitness, EPSILON)) / totalFitness;
        for(int i=1;i<POPULATION_SIZE;i++)
            individualProbability[i] = ((1.0 / max(population[i].fitness, EPSILON)) / totalFitness) + individualProbability[i-1];     

        //picking parents
        array<Individual, POPULATION_SIZE> children;
        //up to top 5 get put in immediately, but with all 16 bytes flipped
        priority_queue<Individual> pq;
        for(int i=0;i<POPULATION_SIZE;i++)
            pq.push(population[i]);
        set<Individual> duplicatePrevention;
        Individual temp;
        while(duplicatePrevention.size() < 5 && !pq.empty())
        {
            temp = pq.top();
            pq.pop();
            Crypto::flipBytes(temp.key);
            temp.fitness = calculateFitness(temp.key, tMatrixControl);
            duplicatePrevention.insert(temp);
        }
        int tempIndex = 0;
        for (const Individual& ind : duplicatePrevention)
        {
            cout << ind.fitness << endl;
            cout << Crypto::hammingDistanceBits(GLOBAL_KEY, ind.key) << endl;
            if(ind.fitness == 0)
            {
                if(isGoal(ind.key, plainText, cipherText))
                {
                    bestChild = ind;
                    found = true;
                    tempIndex = 100;
                    break;
                }
            }
            children[tempIndex] = ind;
            tempIndex++;
        }


        //picking remaining parents
        for(int i=tempIndex;i<POPULATION_SIZE;i++)
        {
            double randomDouble = (double) rand() / RAND_MAX;
            array<unsigned char, 16> parentOne, parentTwo;

            //first parent
            for(int j=0;j<POPULATION_SIZE;j++)
            {
                if(randomDouble < individualProbability[j])
                {
                    parentOne = population[j].key;
                    break;
                }
            }

            //second parent
            bool parentTwoFound = false;
            while(!parentTwoFound)
            {
                randomDouble = ((double) rand() / RAND_MAX);
                for(int j=0;j<POPULATION_SIZE;j++)
                {
                    if(randomDouble < individualProbability[j])
                    {
                        parentTwo = population[j].key;
                        parentTwoFound = true;
                        break;
                    }
                }
            }

            //crossover
            int randomInt = rand () % 16;//crossover index
            Individual child;
            if( (rand() % 2) == 0)
            {
                for(int index = 0; index<randomInt;index++)
                    child.key[index] = parentOne[index];
                for(int index = randomInt; index < 16; index++)
                    child.key[index] = parentTwo[index];
            }
            else
            {
                for(int index = 0; index<randomInt;index++)
                    child.key[index] = parentTwo[index];
                for(int index = randomInt; index < 16; index++)
                    child.key[index] = parentOne[index];
            }


            //mutation
            for(int j=0;j<16;j++)
            {
                randomDouble = (double) rand() / RAND_MAX;
                if(randomDouble < mutationRate)
                    child.key[j] = rand () % 16;//not guaranteed to be different
            }

            child.fitness = calculateFitness(child.key, tMatrixControl);
            cout << child.fitness << endl;
            cout << Crypto::hammingDistanceBits(GLOBAL_KEY, child.key) << endl;
            children[i] = child;

            if(child.fitness == 0)
            {
                if(isGoal(child.key, plainText, cipherText))
                {
                    bestChild = child;
                    found = true;
                    break;
                }
            }

        }
        generationNum++;
        population = children;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << duration.count() << endl;

    cout << "Found key is \n" ;
    for(int i=0;i<16;i++)
        cout << (int) bestChild.key[i];
    cout << endl;
}

bool isGoal(const array<unsigned char, 16>&key, const array<unsigned char, 16> &plainText, const array<unsigned char, 16> &cipherText)
{
    array<unsigned char, 16> state = plainText;
    AES aes;
    aes.encrypt(state, key);
    if(state == cipherText)
        return true;
    return false;
}

void initPop(int, array<Individual, POPULATION_SIZE> &p, const array<array<double, 2>,2> &tMatrixControl)
{
    Individual ind;
    set<array<unsigned char, 16>> keySet;
    int index = 0;
    while(keySet.size() < POPULATION_SIZE)
    {
        Crypto::generateRandomKey(ind.key);
        if(keySet.insert(ind.key).second)
        {
            ind.fitness = calculateFitness(ind.key, tMatrixControl);
            p[index] = ind;
            index++;
        }
    }
}

double calculateFitness(const array<unsigned char, 16> &keyVariant, const array<array<double, 2>,2> &tMatrixControl)
{
    Huffman huffman(keyVariant);
    array<array<double, 2>,2> tMatrixVariant;
    Markov::generateMarkovTransitionMatrix(huffman.getHuffmanCodes(), tMatrixVariant);
    double diff = Crypto::markovDifference(tMatrixControl, tMatrixVariant);
    return diff;
}